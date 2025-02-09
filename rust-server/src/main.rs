use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use clap::{Arg, App};

const BUFFER_SIZE: usize = 1024;
const MAX_TIME_DIFF_EARLY: u64 = 10; // 10 seconds
const MAX_TIME_DIFF_LATE: u64 = 4 * 60 * 60; // 4 hours

type HmacSha256 = Hmac<Sha256>;

fn ipv4_from_ip(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(ipv4) => Some(ipv4),
        IpAddr::V6(ipv6) => ipv6.to_ipv4(),
    }
}

fn main() -> io::Result<()> {
    let matches = App::new("UDP Ping Server")
        .version("0.1.0")
        .arg(
            Arg::with_name("seed")
                .short("s")
                .long("seed")
                .value_name("SEED")
                .help("Sets the HMAC-SHA256 seed")
                .takes_value(true),
        )
        .get_matches();

    let seed = matches.value_of("seed").map(|s| s.as_bytes().to_vec());
    let port = 444;

    let socket = UdpSocket::bind(format!("[::]:{}", port))?;
    socket.set_nonblocking(true)?;

    println!("Server running on port {}", port);

    let mut buf = [0u8; BUFFER_SIZE];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, src_addr)) => {
                let buffer = &buf[..len];

                // Basic packet validation
                if buffer.len() < 28 || &buffer[0..4] != b"RP01" {
                    continue;
                }

                println!("len match");

                // Extract components
                // let sequence = &buffer[4..8];
                let packet_time = u32::from_be_bytes(buffer[8..12].try_into().unwrap()) as u64;
                let packet_hash = &buffer[12..28]; // 16 bytes for truncated HMAC

                // Validate time
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                if packet_time > current_time + MAX_TIME_DIFF_EARLY ||
                    packet_time < current_time - MAX_TIME_DIFF_LATE {
                    continue;
                }
                println!("time match");

                println!("Source IP address: {}", src_addr.ip());



                let res_ip = ipv4_from_ip(src_addr.ip());

                // Convert Option<Ipv4Addr> to String
                let res_ip_str = match res_ip {
                    Some(ipv4) => ipv4.to_string(),
                    None => "Not an IPv4 address".to_string(),
                };


                println!("HMAC IP address: {:?}", res_ip_str);

                // Validate HMAC if seed provided
                if let Some(seed) = &seed {
                    let mut mac = HmacSha256::new_from_slice(seed).unwrap();
                    mac.update(res_ip_str.as_bytes());
                    mac.update(&packet_time.to_be_bytes());
                    let expected_hash = &mac.finalize().into_bytes()[..16];

                    if packet_hash != expected_hash {
                        println!("hash mismatch");
                        continue;
                    }
                    println!("hash match");
                }

                // Send response (RR01 + sequence)
                let response = [b'R', b'R', b'0', b'1',
                    buffer[4], buffer[5], buffer[6], buffer[7]];
                let _ = socket.send_to(&response, src_addr);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No data available, sleep briefly
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                break;
            }
        }
    }

    Ok(())
}