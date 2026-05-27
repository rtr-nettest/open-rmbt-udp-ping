use std::io;
use std::net::{SocketAddr, SocketAddrV6, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Arg, Command};
use hmac::{Hmac, Mac};
use log::{debug, error, info, Level, LevelFilter, Log, Metadata, Record};
use sha2::Sha256;
use socket2::{Domain, Protocol, Socket, Type};

const BUFFER_SIZE: usize = 1024;
const MAX_TIME_DIFF_EARLY: u64 = 30;
const MAX_TIME_DIFF_LATE: u64 = 4 * 60 * 60;

type HmacSha256 = Hmac<Sha256>;

static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

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

fn main() {
    let matches = Command::new("UDP Ping Server")
        .version("1.1.0")
        .arg(
            Arg::new("seed")
                .short('s')
                .long("seed")
                .value_name("SEED")
                .help("HMAC-SHA256 seed"),
        )
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .value_name("N")
                .help("Number of worker threads (default: logical CPU count)"),
        )
        .arg(
            Arg::new("debug")
                .short('d')
                .long("debug")
                .action(clap::ArgAction::SetTrue)
                .help("Enable debug logging"),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .help("Port to listen on (default: 444)"),
        )
        .get_matches();

    let debug_flag = matches.get_flag("debug");
    DEBUG_ENABLED.store(debug_flag, Ordering::Relaxed);
    log::set_boxed_logger(Box::new(DynamicLogger)).unwrap();
    log::set_max_level(LevelFilter::Debug);

    let seed: Option<Vec<u8>> = matches
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

    let socket = Arc::new(setup_socket(port).expect("Failed to bind socket"));

    info!("Server running on port {} ({} threads)", port, num_threads);

    #[cfg(unix)]
    setup_signal_handler();

    let handles: Vec<_> = (0..num_threads)
        .map(|idx| {
            let socket = socket.clone();
            let seed = seed.clone();
            thread::spawn(move || {
                debug!("Worker {} started", idx);
                worker_thread(socket, seed);
            })
        })
        .collect();

    for handle in handles {
        handle.join().ok();
    }
}

#[cfg(unix)]
fn setup_signal_handler() {
    use signal_hook::consts::SIGUSR1;
    use signal_hook::iterator::Signals;

    let mut signals = Signals::new([SIGUSR1]).expect("Failed to set up signal handler");
    thread::spawn(move || {
        for _ in signals.forever() {
            let prev = DEBUG_ENABLED.fetch_xor(true, Ordering::Relaxed);
            eprintln!("Debug logging {}", if !prev { "enabled" } else { "disabled" });
        }
    });
}

fn worker_thread(socket: Arc<UdpSocket>, seed: Option<Vec<u8>>) {
    let seed = seed.as_deref();
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let (len, src_addr) = match socket.recv_from(&mut buffer) {
            Ok(r) => r,
            Err(e) => {
                error!("recv_from: {}", e);
                continue;
            }
        };

        let packet = &buffer[..len];
        debug!("Received (len={}): {}", len, hex::encode(packet));

        if len != 24 || &packet[0..4] != b"RP01" {
            continue;
        }

        let packet_time = u32::from_be_bytes(packet[8..12].try_into().unwrap()) as u64;
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        debug!("Time difference: {:.3} s", current_time as f64 - packet_time as f64);

        if packet_time + MAX_TIME_DIFF_LATE < current_time {
            debug!("Packet too late");
            continue;
        }
        if packet_time > current_time + MAX_TIME_DIFF_EARLY {
            debug!("Packet too early");
            continue;
        }

        if let Some(seed) = seed {
            let packet_hash = &packet[12..20];
            let mut mac = HmacSha256::new_from_slice(seed).unwrap();
            mac.update(&(packet_time as u32).to_be_bytes());
            debug!("HMAC packet: {}", hex::encode(packet_hash));
            if packet_hash != &mac.finalize().into_bytes()[..8] {
                debug!("HMAC packet mismatch");
                continue;
            }
            debug!("HMAC packet matches");
        }

        let src_v6 = to_v6(src_addr);
        debug!("Source address: {} ({:032x})", src_v6.ip(), src_v6.ip().to_bits());

        let ip_match = if let Some(seed) = seed {
            let packet_ip_hash = &packet[20..24];
            let mut mac_ip = HmacSha256::new_from_slice(seed).unwrap();
            mac_ip.update(&(packet_time as u32).to_be_bytes());
            mac_ip.update(&src_v6.ip().to_bits().to_be_bytes());
            let expected = mac_ip.finalize().into_bytes();
            debug!(
                "HMAC IP: {} expected: {}",
                hex::encode(packet_ip_hash),
                hex::encode(&expected[..4])
            );
            packet_ip_hash == &expected[..4]
        } else {
            false
        };

        let tag = if ip_match { b"RR01" } else { b"RE01" };
        let mut response = [0u8; 8];
        response[..4].copy_from_slice(tag);
        response[4..].copy_from_slice(&packet[4..8]);
        debug!("Sending response: {}", hex::encode(response));

        if let Err(e) = socket.send_to(&response, src_addr) {
            error!("send_to: {}", e);
        }
    }
}

fn to_v6(addr: SocketAddr) -> SocketAddrV6 {
    match addr {
        SocketAddr::V6(a) => a,
        SocketAddr::V4(a) => SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0),
    }
}

fn setup_socket(port: u16) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_only_v6(false)?;
    let addr: SocketAddr = format!("[::]:{}", port).parse().unwrap();
    socket.bind(&addr.into())?;
    Ok(socket.into())
}
