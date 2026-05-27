use std::net::{SocketAddr, SocketAddrV6};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use log::debug;
use sha2::Sha256;

/// A packet whose timestamp is more than this many seconds in the future is rejected.
const MAX_TIME_DIFF_EARLY: u64 = 30;

/// A packet whose timestamp is more than this many seconds in the past is rejected.
const MAX_TIME_DIFF_LATE: u64 = 4 * 60 * 60; // 4 hours

type HmacSha256 = Hmac<Sha256>;

/// Validates, authenticates, and produces a response for one UDP packet.
/// Returns `None` when the packet should be silently dropped.
///
/// Expected packet layout (24 bytes total):
/// ```text
/// [0..4]   magic bytes  "RP01"
/// [4..8]   sequence number (echoed unchanged in the response)
/// [8..12]  timestamp: seconds since Unix epoch, big-endian u32
/// [12..20] HMAC-SHA256(seed, timestamp)[0..8]          — timestamp authentication
/// [20..24] HMAC-SHA256(seed, timestamp ‖ src_ip)[0..4] — source-IP authentication
/// ```
pub fn process_packet(packet: &[u8], src_addr: SocketAddr, seed: Option<&[u8]>) -> Option<[u8; 8]> {
    if !is_valid_header(packet) {
        return None;
    }

    let packet_time = u32::from_be_bytes(packet[8..12].try_into().unwrap());

    if !is_within_time_window(packet_time) {
        return None;
    }

    // When a seed is configured, verify the timestamp HMAC before any further processing.
    if let Some(seed) = seed {
        if !verify_packet_hmac(seed, packet_time, &packet[12..20]) {
            debug!("HMAC packet mismatch — dropping");
            return None;
        }
    }

    let src_v6 = to_v6(src_addr);
    debug!("Source address: {} ({:032x})", src_v6.ip(), src_v6.ip().to_bits());

    // The IP HMAC confirms the packet was not replayed from a different source address.
    // Without a seed there is no way to verify this, so ip_match stays false → RE01 tag.
    let ip_match = seed.map_or(false, |seed| {
        verify_ip_hmac(seed, packet_time, src_v6, &packet[20..24])
    });

    Some(build_response(ip_match, &packet[4..8]))
}

/// Returns `true` when the packet starts with the `RP01` magic and is exactly 24 bytes.
fn is_valid_header(packet: &[u8]) -> bool {
    packet.len() == 24 && packet[0..4] == *b"RP01"
}

/// Returns `true` when `packet_time` is within the acceptable clock-skew window.
/// Rejects packets that are too old (potential replay) or too far in the future (clock error).
fn is_within_time_window(packet_time: u32) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let packet_time = packet_time as u64;

    debug!("Time difference: {:.3} s", now as f64 - packet_time as f64);

    if packet_time + MAX_TIME_DIFF_LATE < now {
        debug!("Packet too late — dropping");
        return false;
    }
    if packet_time > now + MAX_TIME_DIFF_EARLY {
        debug!("Packet too early — dropping");
        return false;
    }
    true
}

/// Returns `true` when `hash` matches the first 8 bytes of HMAC-SHA256(seed, timestamp).
/// Authenticates that the sender knows the shared secret and used the correct timestamp.
fn verify_packet_hmac(seed: &[u8], packet_time: u32, hash: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(seed).unwrap();
    mac.update(&packet_time.to_be_bytes());
    let expected = mac.finalize().into_bytes();
    debug!("HMAC packet received={} expected={}", hex::encode(hash), hex::encode(&expected[..8]));
    hash == &expected[..8]
}

/// Returns `true` when `hash` matches the first 4 bytes of HMAC-SHA256(seed, timestamp ‖ src_ip).
/// The source IP is always treated as a 128-bit IPv6 value (IPv4 addresses are mapped first)
/// to keep the HMAC input format consistent regardless of address family.
fn verify_ip_hmac(seed: &[u8], packet_time: u32, src: SocketAddrV6, hash: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(seed).unwrap();
    mac.update(&packet_time.to_be_bytes());
    mac.update(&src.ip().to_bits().to_be_bytes()); // 128-bit big-endian
    let expected = mac.finalize().into_bytes();
    debug!("HMAC IP received={} expected={}", hex::encode(hash), hex::encode(&expected[..4]));
    hash == &expected[..4]
}

/// Builds the 8-byte response packet.
///
/// | Condition          | Tag   | Meaning                              |
/// |--------------------|-------|--------------------------------------|
/// | IP HMAC matched    | `RR01`| Source address confirmed              |
/// | IP HMAC mismatch   | `RE01`| Packet echoed, but origin unverified  |
///
/// Bytes 4–7 always echo back the sequence number from the request.
fn build_response(ip_match: bool, seq: &[u8]) -> [u8; 8] {
    let mut response = [0u8; 8];
    response[..4].copy_from_slice(if ip_match { b"RR01" } else { b"RE01" });
    response[4..].copy_from_slice(seq);
    response
}

/// Normalises any `SocketAddr` to an IPv6 representation.
/// IPv4 addresses are mapped to `::ffff:a.b.c.d` so all HMAC inputs use the same 128-bit format.
fn to_v6(addr: SocketAddr) -> SocketAddrV6 {
    match addr {
        SocketAddr::V6(a) => a,
        SocketAddr::V4(a) => SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::Mac;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Current Unix time as a u32 (safe until year 2106).
    fn now_secs() -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32
    }

    /// A fixed IPv6 source address used across tests.
    fn sample_src() -> SocketAddrV6 {
        SocketAddrV6::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1), 1234, 0, 0)
    }

    /// Builds a valid 24-byte RP01 packet.
    ///
    /// When `seed` is `Some`, the HMAC fields are computed correctly for the given
    /// `packet_time` and `src` address. When `seed` is `None`, the HMAC fields are
    /// zeroed — still accepted by `process_packet` when called with `seed = None`.
    fn make_packet(seed: Option<&[u8]>, seq: &[u8; 4], packet_time: u32, src: SocketAddrV6) -> [u8; 24] {
        let mut p = [0u8; 24];
        p[0..4].copy_from_slice(b"RP01");
        p[4..8].copy_from_slice(seq);
        p[8..12].copy_from_slice(&packet_time.to_be_bytes());

        if let Some(seed) = seed {
            // Timestamp HMAC: first 8 bytes of HMAC-SHA256(seed, timestamp)
            let mut mac = HmacSha256::new_from_slice(seed).unwrap();
            mac.update(&packet_time.to_be_bytes());
            p[12..20].copy_from_slice(&mac.finalize().into_bytes()[..8]);

            // IP HMAC: first 4 bytes of HMAC-SHA256(seed, timestamp ‖ src_ip_128bit)
            let mut mac = HmacSha256::new_from_slice(seed).unwrap();
            mac.update(&packet_time.to_be_bytes());
            mac.update(&src.ip().to_bits().to_be_bytes());
            p[20..24].copy_from_slice(&mac.finalize().into_bytes()[..4]);
        }

        p
    }

    // ── is_valid_header ───────────────────────────────────────────────────────

    #[test]
    fn header_valid() {
        let mut p = [0u8; 24];
        p[0..4].copy_from_slice(b"RP01");
        assert!(is_valid_header(&p));
    }

    #[test]
    fn header_wrong_magic_rejected() {
        let mut p = [0u8; 24];
        p[0..4].copy_from_slice(b"RP02");
        assert!(!is_valid_header(&p));
    }

    #[test]
    fn header_too_short_rejected() {
        assert!(!is_valid_header(&[0u8; 23]));
    }

    #[test]
    fn header_too_long_rejected() {
        assert!(!is_valid_header(&[0u8; 25]));
    }

    // ── is_within_time_window ─────────────────────────────────────────────────

    #[test]
    fn time_current_accepted() {
        assert!(is_within_time_window(now_secs()));
    }

    #[test]
    fn time_just_inside_early_limit_accepted() {
        // MAX_TIME_DIFF_EARLY - 1 seconds in the future must still be accepted.
        assert!(is_within_time_window(now_secs() + MAX_TIME_DIFF_EARLY as u32 - 1));
    }

    #[test]
    fn time_past_early_limit_rejected() {
        assert!(!is_within_time_window(now_secs() + MAX_TIME_DIFF_EARLY as u32 + 2));
    }

    #[test]
    fn time_just_inside_late_limit_accepted() {
        // One second before the late cutoff must still be accepted.
        assert!(is_within_time_window(now_secs() - MAX_TIME_DIFF_LATE as u32 + 1));
    }

    #[test]
    fn time_past_late_limit_rejected() {
        assert!(!is_within_time_window(now_secs() - MAX_TIME_DIFF_LATE as u32 - 10));
    }

    // ── verify_packet_hmac ────────────────────────────────────────────────────

    #[test]
    fn packet_hmac_correct_seed_accepted() {
        let seed = b"test-seed";
        let t: u32 = 1_700_000_000;
        let mut mac = HmacSha256::new_from_slice(seed).unwrap();
        mac.update(&t.to_be_bytes());
        let hash = mac.finalize().into_bytes();
        assert!(verify_packet_hmac(seed, t, &hash[..8]));
    }

    #[test]
    fn packet_hmac_wrong_seed_rejected() {
        let t: u32 = 1_700_000_000;
        let mut mac = HmacSha256::new_from_slice(b"correct-seed").unwrap();
        mac.update(&t.to_be_bytes());
        let hash = mac.finalize().into_bytes();
        assert!(!verify_packet_hmac(b"wrong-seed", t, &hash[..8]));
    }

    #[test]
    fn packet_hmac_corrupted_hash_rejected() {
        let seed = b"test-seed";
        let t: u32 = 1_700_000_000;
        let mut mac = HmacSha256::new_from_slice(seed).unwrap();
        mac.update(&t.to_be_bytes());
        let mut hash = mac.finalize().into_bytes()[..8].to_vec();
        hash[0] ^= 0xFF; // flip one bit
        assert!(!verify_packet_hmac(seed, t, &hash));
    }

    // ── verify_ip_hmac ────────────────────────────────────────────────────────

    #[test]
    fn ip_hmac_correct_ipv6_accepted() {
        let seed = b"test-seed";
        let t: u32 = 1_700_000_000;
        let src = SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 1234, 0, 0);
        let mut mac = HmacSha256::new_from_slice(seed).unwrap();
        mac.update(&t.to_be_bytes());
        mac.update(&src.ip().to_bits().to_be_bytes());
        let hash = mac.finalize().into_bytes();
        assert!(verify_ip_hmac(seed, t, src, &hash[..4]));
    }

    #[test]
    fn ip_hmac_different_ip_rejected() {
        let seed = b"test-seed";
        let t: u32 = 1_700_000_000;
        let real = SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 1234, 0, 0);
        let spoofed = SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2), 1234, 0, 0);
        let mut mac = HmacSha256::new_from_slice(seed).unwrap();
        mac.update(&t.to_be_bytes());
        mac.update(&real.ip().to_bits().to_be_bytes());
        let hash = mac.finalize().into_bytes();
        // Hash was computed for `real` but we pass `spoofed` — must fail.
        assert!(!verify_ip_hmac(seed, t, spoofed, &hash[..4]));
    }

    #[test]
    fn ip_hmac_correct_ipv4_mapped_accepted() {
        // IPv4-mapped addresses (::ffff:x.x.x.x) must hash correctly.
        let seed = b"test-seed";
        let t: u32 = 1_700_000_000;
        let mapped = SocketAddrV6::new(Ipv4Addr::new(192, 168, 1, 1).to_ipv6_mapped(), 5678, 0, 0);
        let mut mac = HmacSha256::new_from_slice(seed).unwrap();
        mac.update(&t.to_be_bytes());
        mac.update(&mapped.ip().to_bits().to_be_bytes());
        let hash = mac.finalize().into_bytes();
        assert!(verify_ip_hmac(seed, t, mapped, &hash[..4]));
    }

    // ── build_response ────────────────────────────────────────────────────────

    #[test]
    fn response_rr01_when_ip_matched() {
        let seq = [1u8, 2, 3, 4];
        let r = build_response(true, &seq);
        assert_eq!(&r[..4], b"RR01");
        assert_eq!(&r[4..], &seq);
    }

    #[test]
    fn response_re01_when_ip_not_matched() {
        let seq = [5u8, 6, 7, 8];
        let r = build_response(false, &seq);
        assert_eq!(&r[..4], b"RE01");
        assert_eq!(&r[4..], &seq);
    }

    #[test]
    fn response_seq_echoed_unchanged() {
        let seq = [0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(&build_response(true, &seq)[4..], &seq);
        assert_eq!(&build_response(false, &seq)[4..], &seq);
    }

    // ── to_v6 ─────────────────────────────────────────────────────────────────

    #[test]
    fn to_v6_passes_ipv6_unchanged() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let addr = SocketAddr::V6(SocketAddrV6::new(ip, 9999, 0, 0));
        let v6 = to_v6(addr);
        assert_eq!(*v6.ip(), ip);
        assert_eq!(v6.port(), 9999);
    }

    #[test]
    fn to_v6_maps_ipv4_to_ipv4_mapped() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, 4321));
        let v6 = to_v6(addr);
        assert_eq!(*v6.ip(), ip.to_ipv6_mapped());
        assert_eq!(v6.port(), 4321);
    }

    // ── process_packet ────────────────────────────────────────────────────────

    #[test]
    fn process_no_seed_returns_re01() {
        let seq = [1u8, 2, 3, 4];
        let src = sample_src();
        let p = make_packet(None, &seq, now_secs(), src);
        let r = process_packet(&p, SocketAddr::V6(src), None).unwrap();
        assert_eq!(&r[..4], b"RE01");
        assert_eq!(&r[4..], &seq);
    }

    #[test]
    fn process_with_seed_and_matching_ip_returns_rr01() {
        let seed = b"test-seed";
        let seq = [9u8, 8, 7, 6];
        let src = sample_src();
        let p = make_packet(Some(seed), &seq, now_secs(), src);
        let r = process_packet(&p, SocketAddr::V6(src), Some(seed)).unwrap();
        assert_eq!(&r[..4], b"RR01");
        assert_eq!(&r[4..], &seq);
    }

    #[test]
    fn process_wrong_magic_dropped() {
        let src = sample_src();
        let mut p = make_packet(None, &[0; 4], now_secs(), src);
        p[0] = b'X'; // corrupt the magic bytes
        assert!(process_packet(&p, SocketAddr::V6(src), None).is_none());
    }

    #[test]
    fn process_too_short_dropped() {
        let src = SocketAddr::V6(sample_src());
        assert!(process_packet(&[0u8; 10], src, None).is_none());
    }

    #[test]
    fn process_expired_timestamp_dropped() {
        let seed = b"test-seed";
        let src = sample_src();
        let old = now_secs() - MAX_TIME_DIFF_LATE as u32 - 10;
        let p = make_packet(Some(seed), &[0; 4], old, src);
        assert!(process_packet(&p, SocketAddr::V6(src), Some(seed)).is_none());
    }

    #[test]
    fn process_future_timestamp_dropped() {
        let seed = b"test-seed";
        let src = sample_src();
        let future = now_secs() + MAX_TIME_DIFF_EARLY as u32 + 10;
        let p = make_packet(Some(seed), &[0; 4], future, src);
        assert!(process_packet(&p, SocketAddr::V6(src), Some(seed)).is_none());
    }

    #[test]
    fn process_corrupted_packet_hmac_dropped() {
        let seed = b"test-seed";
        let src = sample_src();
        let mut p = make_packet(Some(seed), &[0; 4], now_secs(), src);
        p[12] ^= 0xFF; // flip bits inside the timestamp HMAC field
        assert!(process_packet(&p, SocketAddr::V6(src), Some(seed)).is_none());
    }

    #[test]
    fn process_spoofed_source_ip_returns_re01() {
        // Packet is correctly signed for `real_src` but arrives from a different address.
        // The timestamp HMAC still passes; only the IP HMAC fails → RE01.
        let seed = b"test-seed";
        let seq = [1u8, 2, 3, 4];
        let real_src = sample_src();
        let p = make_packet(Some(seed), &seq, now_secs(), real_src);

        let spoofed = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            9999,
            0,
            0,
        ));
        let r = process_packet(&p, spoofed, Some(seed)).unwrap();
        assert_eq!(&r[..4], b"RE01");
        assert_eq!(&r[4..], &seq);
    }

    #[test]
    fn process_ipv4_source_correctly_mapped_to_rr01() {
        // On dual-stack sockets the OS delivers IPv4 clients as SocketAddr::V4.
        // The HMAC must be computed using the IPv4-mapped IPv6 form (::ffff:x.x.x.x).
        let seed = b"test-seed";
        let seq = [0xAu8, 0xB, 0xC, 0xD];
        let ipv4 = Ipv4Addr::new(10, 0, 0, 1);
        let mapped = SocketAddrV6::new(ipv4.to_ipv6_mapped(), 5678, 0, 0);
        // Build the packet using the mapped address so the HMAC is correct.
        let p = make_packet(Some(seed), &seq, now_secs(), mapped);
        // Simulate what recv_from returns for an IPv4 client on a dual-stack socket.
        let src_addr = SocketAddr::V4(SocketAddrV4::new(ipv4, 5678));
        let r = process_packet(&p, src_addr, Some(seed)).unwrap();
        assert_eq!(&r[..4], b"RR01");
        assert_eq!(&r[4..], &seq);
    }
}
