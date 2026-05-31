use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn build_seed_packet(seq: u32, seed: &str, source_ip: IpAddr) -> [u8; 24] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let time_bytes = now.to_be_bytes();

    let mut mac = HmacSha256::new_from_slice(seed.as_bytes()).expect("HMAC key error");
    mac.update(&time_bytes);
    let time_hash = mac.finalize().into_bytes();

    let ip_v6 = match source_ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };

    let mut mac_ip = HmacSha256::new_from_slice(seed.as_bytes()).expect("HMAC key error");
    mac_ip.update(&time_bytes);
    mac_ip.update(&ip_v6.octets());
    let ip_hash = mac_ip.finalize().into_bytes();

    let mut packet = [0u8; 24];
    packet[0..4].copy_from_slice(b"RP01");
    packet[4..8].copy_from_slice(&seq.to_be_bytes());
    packet[8..12].copy_from_slice(&time_bytes);
    packet[12..20].copy_from_slice(&time_hash[..8]);
    packet[20..24].copy_from_slice(&ip_hash[..4]);
    packet
}

pub fn build_token_packet(seq: u32, token: &[u8; 16]) -> [u8; 24] {
    let mut packet = [0u8; 24];
    packet[0..4].copy_from_slice(b"RP01");
    packet[4..8].copy_from_slice(&seq.to_be_bytes());
    packet[8..24].copy_from_slice(token);
    packet
}

pub fn parse_response(data: &[u8]) -> Option<([u8; 4], u32)> {
    if data.len() != 8 {
        return None;
    }
    let tag: [u8; 4] = data[0..4].try_into().unwrap();
    if tag != *b"RR01" && tag != *b"RE01" {
        return None;
    }
    let seq = u32::from_be_bytes(data[4..8].try_into().unwrap());
    Some((tag, seq))
}
