//! UDP Ping Server
//!
//! Listens on one or more IP addresses and responds to `RP01` ping packets.
//! Optional HMAC-SHA256 authentication verifies both the packet timestamp and
//! the source IP address to prevent spoofing and replay attacks.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Arg, ArgAction, Command};
use hmac::{Hmac, Mac};
use log::{debug, error, info, Level, LevelFilter, Log, Metadata, Record};
use sha2::Sha256;
use socket2::{Domain, Protocol, Socket, Type};

// ── Constants ─────────────────────────────────────────────────────────────────

const BUFFER_SIZE: usize = 1024;

/// A packet whose timestamp is more than this many seconds in the future is rejected.
const MAX_TIME_DIFF_EARLY: u64 = 30;

/// A packet whose timestamp is more than this many seconds in the past is rejected.
const MAX_TIME_DIFF_LATE: u64 = 4 * 60 * 60; // 4 hours

type HmacSha256 = Hmac<Sha256>;

// ── Logger ────────────────────────────────────────────────────────────────────

/// Toggled at runtime (SIGUSR1 on Unix) to turn debug output on/off without restarting.
static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

/// Writes `<unix-seconds> [LEVEL] message` to stderr.
/// Debug messages are suppressed unless `DEBUG_ENABLED` is set.
struct DynamicLogger;

impl Log for DynamicLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        if metadata.level() == Level::Debug {
            DEBUG_ENABLED.load(Ordering::Relaxed)
        } else {
            metadata.level() <= Level::Info
        }
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            eprintln!("{} [{}] {}", now, record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

// ── Config ────────────────────────────────────────────────────────────────────

/// Validated, parsed command-line configuration.
struct Config {
    /// UDP port to listen on.
    port: u16,
    /// Optional HMAC-SHA256 shared secret. When absent, packets are not authenticated.
    seed: Option<Vec<u8>>,
    /// Total number of worker threads to spread across all bound sockets.
    num_threads: usize,
    /// Addresses to bind to. Empty means bind to all interfaces (dual-stack wildcard).
    bind_addrs: Vec<IpAddr>,
}

impl Config {
    /// Parses and validates command-line arguments, populating this struct.
    /// Also installs the initial debug-logging state before returning.
    fn from_args() -> Self {
        let matches = Command::new("UDP Ping Server")
            .version("1.1.0")
            .arg(
                Arg::new("seed")
                    .short('s')
                    .long("seed")
                    .value_name("SEED")
                    .help("HMAC-SHA256 shared secret; omit to accept all packets without authentication"),
            )
            .arg(
                Arg::new("bind")
                    .short('b')
                    .long("bind")
                    .value_name("ADDR")
                    .action(ArgAction::Append)
                    .help("IP address to listen on; may be repeated (default: all interfaces)"),
            )
            .arg(
                Arg::new("threads")
                    .short('t')
                    .long("threads")
                    .value_name("N")
                    .help("Total worker threads, spread across bound addresses (default: logical CPU count)"),
            )
            .arg(
                Arg::new("debug")
                    .short('d')
                    .long("debug")
                    .action(ArgAction::SetTrue)
                    .help("Enable debug logging at startup (also toggled at runtime via SIGUSR1 on Unix)"),
            )
            .arg(
                Arg::new("port")
                    .short('p')
                    .long("port")
                    .value_name("PORT")
                    .help("UDP port to listen on (default: 444)"),
            )
            .get_matches();

        // Apply debug flag early so that any subsequent log::debug! calls are visible.
        DEBUG_ENABLED.store(matches.get_flag("debug"), Ordering::Relaxed);

        let seed = matches
            .get_one::<String>("seed")
            .map(|s| s.as_bytes().to_vec());

        let port = matches
            .get_one::<String>("port")
            .map(|s| s.parse::<u16>().expect("Invalid port number"))
            .unwrap_or(444);

        let num_threads = matches
            .get_one::<String>("threads")
            .map(|s| s.parse::<usize>().expect("Invalid thread count"))
            .unwrap_or_else(|| thread::available_parallelism().map(|n| n.get()).unwrap_or(1));

        let bind_addrs = matches
            .get_many::<String>("bind")
            .map(|vals| {
                vals.map(|s| {
                    s.parse::<IpAddr>().unwrap_or_else(|_| {
                        eprintln!("Invalid IP address: {s}");
                        std::process::exit(1);
                    })
                })
                .collect()
            })
            .unwrap_or_default();

        Config { port, seed, num_threads, bind_addrs }
    }

    /// How many worker threads each socket should receive.
    /// The total thread budget is divided evenly; each socket gets at least one thread.
    fn threads_per_socket(&self, num_sockets: usize) -> usize {
        (self.num_threads / num_sockets).max(1)
    }
}

// ── Server ────────────────────────────────────────────────────────────────────

/// A bound UDP server: one socket per configured address, ready to spawn workers.
struct Server {
    config: Config,
    /// Each element is shared among the worker threads assigned to that socket.
    sockets: Vec<Arc<UdpSocket>>,
}

impl Server {
    /// Binds one UDP socket for every address in `config.bind_addrs`, or a single
    /// dual-stack wildcard socket when no addresses are specified.
    fn bind(config: Config) -> io::Result<Self> {
        let sockets: Vec<Arc<UdpSocket>> = if config.bind_addrs.is_empty() {
            info!("Listening on all interfaces, port {}", config.port);
            vec![Arc::new(setup_socket(None, config.port)?)]
        } else {
            config
                .bind_addrs
                .iter()
                .map(|&addr| {
                    info!("Listening on {addr}, port {}", config.port);
                    setup_socket(Some(addr), config.port)
                        .map(Arc::new)
                        .unwrap_or_else(|e| panic!("Failed to bind to {addr}: {e}"))
                })
                .collect()
        };

        Ok(Server { config, sockets })
    }

    /// Spawns worker threads and blocks until they all exit.
    /// Under normal operation the threads loop forever, so this never returns.
    fn run(self) {
        let threads_per_socket = self.config.threads_per_socket(self.sockets.len());
        info!("{} socket(s), {threads_per_socket} thread(s) each", self.sockets.len());

        let handles: Vec<JoinHandle<()>> = self
            .sockets
            .iter()
            .flat_map(|socket| {
                // Each socket gets its own slice of threads; clone the Arc once per socket.
                let socket = socket.clone();
                let seed = self.config.seed.clone();
                (0..threads_per_socket).map(move |idx| {
                    let socket = socket.clone();
                    let seed = seed.clone();
                    thread::spawn(move || {
                        debug!("Worker {idx} started on {}", socket.local_addr().unwrap());
                        worker_loop(socket, seed);
                    })
                })
            })
            .collect();

        for handle in handles {
            handle.join().ok();
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    // Install logger first so that messages from Config::from_args() are visible.
    log::set_boxed_logger(Box::new(DynamicLogger)).unwrap();
    log::set_max_level(LevelFilter::Debug);

    let config = Config::from_args();

    // On Unix, SIGUSR1 toggles DEBUG_ENABLED at runtime without restarting the server.
    #[cfg(unix)]
    setup_signal_handler();

    Server::bind(config)
        .expect("Failed to bind server sockets")
        .run();
}

// ── Signal handling (Unix only) ───────────────────────────────────────────────

/// Spawns a background thread that listens for SIGUSR1 and flips `DEBUG_ENABLED`.
#[cfg(unix)]
fn setup_signal_handler() {
    use signal_hook::consts::SIGUSR1;
    use signal_hook::iterator::Signals;

    let mut signals = Signals::new([SIGUSR1]).expect("Failed to register SIGUSR1 handler");
    thread::spawn(move || {
        for _ in signals.forever() {
            let prev = DEBUG_ENABLED.fetch_xor(true, Ordering::Relaxed);
            eprintln!("Debug logging {}", if !prev { "enabled" } else { "disabled" });
        }
    });
}

// ── Worker loop ───────────────────────────────────────────────────────────────

/// Runs forever: receives UDP packets and writes a response for each valid one.
///
/// Because each socket is bound to a specific local address, `send_to` automatically
/// uses that address as the source IP — so replies always come from the same IP the
/// client originally addressed.
fn worker_loop(socket: Arc<UdpSocket>, seed: Option<Vec<u8>>) {
    let seed = seed.as_deref();
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        let (len, src_addr) = match socket.recv_from(&mut buffer) {
            Ok(r) => r,
            Err(e) => {
                error!("recv_from: {e}");
                continue;
            }
        };

        debug!("Received (len={len}): {}", hex::encode(&buffer[..len]));

        if let Some(response) = process_packet(&buffer[..len], src_addr, seed) {
            debug!("Sending response: {}", hex::encode(response));
            if let Err(e) = socket.send_to(&response, src_addr) {
                error!("send_to: {e}");
            }
        }
    }
}

// ── Packet processing ─────────────────────────────────────────────────────────

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
fn process_packet(packet: &[u8], src_addr: SocketAddr, seed: Option<&[u8]>) -> Option<[u8; 8]> {
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

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Normalises any `SocketAddr` to an IPv6 representation.
/// IPv4 addresses are mapped to `::ffff:a.b.c.d` so all HMAC inputs use the same 128-bit format.
fn to_v6(addr: SocketAddr) -> SocketAddrV6 {
    match addr {
        SocketAddr::V6(a) => a,
        SocketAddr::V4(a) => SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0),
    }
}

/// Creates and binds a UDP socket.
///
/// | `bind_addr`         | Socket family | Notes                                   |
/// |---------------------|---------------|-----------------------------------------|
/// | `None` (wildcard)   | IPv6          | `IPV6_V6ONLY=false` → accepts IPv4 too  |
/// | `Some(IPv4 address)`| IPv4          | dedicated IPv4 socket                   |
/// | `Some(IPv6 address)`| IPv6          | dedicated IPv6 socket, v6-only          |
fn setup_socket(bind_addr: Option<IpAddr>, port: u16) -> io::Result<UdpSocket> {
    match bind_addr {
        None => {
            // Dual-stack wildcard: one socket handles both IPv4 and IPv6 clients.
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_reuse_address(true)?;
            socket.set_only_v6(false)?; // accept IPv4-mapped addresses (::ffff:x.x.x.x)
            socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
            Ok(socket.into())
        }
        Some(ip) => {
            // Specific address: choose the right socket family automatically.
            let domain = if ip.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_reuse_address(true)?;
            socket.bind(&SocketAddr::new(ip, port).into())?;
            Ok(socket.into())
        }
    }
}
