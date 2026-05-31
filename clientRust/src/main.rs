use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use std::{process, thread};

use base64::Engine;
use clap::Parser;

mod packet;
mod stats;

#[derive(Parser)]
#[command(about = "UDP Ping Client with HMAC-SHA256 validation")]
struct Args {
    /// Hostname of the server
    #[arg(long)]
    host: String,

    /// Server port
    #[arg(long, default_value = "444")]
    port: u16,

    /// Seed for HMAC computation
    #[arg(long)]
    seed: Option<String>,

    /// Source IP for HMAC calculation
    #[arg(long = "ip")]
    source_ip: Option<String>,

    /// Base64 encoded pre-computed token
    #[arg(long)]
    token: Option<String>,
}

fn main() {
    let args = Args::parse();

    if args.token.is_some() && (args.seed.is_some() || args.source_ip.is_some()) {
        eprintln!("--token cannot be used with --seed or --ip");
        process::exit(1);
    }
    if args.token.is_none() && !(args.seed.is_some() && args.source_ip.is_some()) {
        eprintln!("either --token or both --seed and --ip are required");
        process::exit(1);
    }

    let token_bytes: Option<[u8; 16]> = args.token.as_deref().map(|t| {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(t)
            .unwrap_or_else(|e| {
                eprintln!("invalid base64 token: {e}");
                process::exit(1);
            });
        if bytes.len() != 16 {
            eprintln!("token must be exactly 16 bytes (got {})", bytes.len());
            process::exit(1);
        }
        bytes.try_into().unwrap()
    });

    let source_ip: Option<IpAddr> = args.source_ip.as_deref().map(|s| {
        s.parse().unwrap_or_else(|_| {
            eprintln!("invalid IP address: {s}");
            process::exit(1);
        })
    });

    let server_addr = format!("{}:{}", args.host, args.port);
    let sock_addr = server_addr
        .to_socket_addrs()
        .unwrap_or_else(|e| {
            eprintln!("cannot resolve {}: {e}", args.host);
            process::exit(1);
        })
        .next()
        .unwrap_or_else(|| {
            eprintln!("no address found for {}", args.host);
            process::exit(1);
        });

    let bind = if sock_addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let socket = UdpSocket::bind(bind).unwrap_or_else(|e| {
        eprintln!("bind failed: {e}");
        process::exit(1);
    });
    socket.connect(sock_addr).expect("connect failed");
    socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();

    let running = Arc::new(AtomicBool::new(true));
    // seq -> (send_instant, displayed_seq)
    let pending: Arc<Mutex<HashMap<u32, (Instant, u32)>>> = Arc::new(Mutex::new(HashMap::new()));
    let (tx, rx) = mpsc::channel::<([u8; 4], u32, f64)>();

    {
        let r = running.clone();
        ctrlc::set_handler(move || r.store(false, Ordering::SeqCst)).expect("ctrlc failed");
    }

    // Receiver thread
    {
        let socket2 = socket.try_clone().expect("socket clone failed");
        let pending2 = pending.clone();
        let running2 = running.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 64];
            while running2.load(Ordering::Relaxed) {
                match socket2.recv(&mut buf) {
                    Ok(n) => {
                        if let Some((tag, seq)) = packet::parse_response(&buf[..n]) {
                            let recv_time = Instant::now();
                            let entry = pending2.lock().unwrap().remove(&seq);
                            if let Some((send_time, displayed)) = entry {
                                let rtt_ms =
                                    recv_time.duration_since(send_time).as_secs_f64() * 1000.0;
                                let _ = tx.send((tag, displayed, rtt_ms));
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        });
    }

    let mut stat = stats::RttStats::new();
    let start = Instant::now();
    let mut sent: u32 = 0;
    let seq_base: u32 = rand::random();
    let seed = args.seed.as_deref().unwrap_or("");

    while running.load(Ordering::SeqCst) {
        // Drain responses received since last iteration
        while let Ok((tag, displayed, rtt_ms)) = rx.try_recv() {
            stat.add(rtt_ms);
            let label = if tag == *b"RR01" { "Response" } else { "Error response" };
            println!("{label} from {}: seq={displayed} time={rtt_ms:.3} ms", args.host);
        }

        let sequence = seq_base.wrapping_add(sent);
        let displayed = sent + 1;
        pending.lock().unwrap().insert(sequence, (Instant::now(), displayed));

        let pkt = match &token_bytes {
            Some(t) => packet::build_token_packet(sequence, t),
            None => packet::build_seed_packet(sequence, seed, source_ip.unwrap()),
        };

        if let Err(e) = socket.send(&pkt) {
            eprintln!("send error: {e}");
        }
        sent += 1;

        // Report and remove timed-out entries (no response after 5 s)
        {
            let now = Instant::now();
            let mut guard = pending.lock().unwrap();
            let mut timed_out: Vec<u32> = Vec::new();
            guard.retain(|_, (t, d)| {
                if now.duration_since(*t) > Duration::from_secs(5) {
                    timed_out.push(*d);
                    false
                } else {
                    true
                }
            });
            drop(guard);
            for d in timed_out {
                println!("No response from {}: seq={d}", args.host);
            }
        }

        thread::sleep(Duration::from_secs(1));
    }

    // Give the receiver a moment to collect any in-flight responses
    thread::sleep(Duration::from_millis(300));
    while let Ok((tag, displayed, rtt_ms)) = rx.try_recv() {
        stat.add(rtt_ms);
        let label = if tag == *b"RR01" { "Response" } else { "Error response" };
        println!("{label} from {}: seq={displayed} time={rtt_ms:.3} ms", args.host);
    }

    stat.print_summary(sent, start.elapsed(), &args.host);
}
