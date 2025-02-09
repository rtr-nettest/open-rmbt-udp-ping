extern crate core;


use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use libc::{recvmmsg, sendmmsg, mmsghdr, iovec, sockaddr_in6};
use std::mem::{size_of, MaybeUninit};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use clap::{Arg, App};

const BATCH_SIZE: usize = 64;
const BUFFER_SIZE: usize = 1024;
const MAX_TIME_DIFF_EARLY: u64 = 10; // 10 seconds
const MAX_TIME_DIFF_LATE: u64 = 4 * 60 * 60; // 4 hours

type HmacSha256 = Hmac<Sha256>;

fn main() -> io::Result<()> {
    // Parse command-line arguments
    let matches = App::new("UDP Ping Server")
        .version("0.1.0")
        .author("Dietmar Zlabinger <dietmar.zlabinger@rtr.at>")
        .about("A UDP ping server with HMAC-SHA256 validation")
        .arg(
            Arg::with_name("seed")
                .short("s") // older version of clap (2.x) expect a string slice (&str), not a char.
                .long("seed")
                .value_name("SEED")
                .help("Sets the HMAC-SHA256 seed")
                .takes_value(true),
        )
        .get_matches();

    let seed = matches.value_of("seed").map(|s| s.as_bytes().to_vec());
    println!("Seed is {:?}",matches.value_of("seed"));

    let port = 444;
    let socket = setup_socket(port)?;
    let socket = Arc::new(socket);

    // debug, restrict to single thread
    let threads = 1; //num_cpus::get();
    for _ in 0..threads {
        let socket_clone = socket.clone();
        let seed_clone = seed.clone();
        thread::spawn(move || {
            if let Err(e) = process_packets(socket_clone, seed_clone) {
                eprintln!("Error processing packets: {}", e);
            }
        });
    }

    println!("Server running on port {} ({} threads)", port, threads);
    thread::park();

    Ok(()) // Explicitly return Ok(())
}

fn setup_socket(port: u16) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;

    let addr: SocketAddr = format!("[::]:{}", port).parse().unwrap();
    socket.bind(&addr.into())?;

    // Enable dual-stack IPv4/IPv6
    //socket.set_only_v6(false)?;

    Ok(socket)
}

fn process_packets(socket: Arc<Socket>, seed: Option<Vec<u8>>) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let mut buffers = [[0u8; BUFFER_SIZE]; BATCH_SIZE];
    let mut response_buffers = [[0u8; 8]; BATCH_SIZE]; // Separate buffer for responses
    let mut iovecs = [MaybeUninit::<iovec>::zeroed(); BATCH_SIZE];
    let mut msgs = [MaybeUninit::<mmsghdr>::zeroed(); BATCH_SIZE];
    let mut addr_storage: [sockaddr_in6; BATCH_SIZE] = unsafe { std::mem::zeroed() };

    // Initialize iovecs and msgs
    for i in 0..BATCH_SIZE {
        iovecs[i].write(iovec {
            iov_base: buffers[i].as_mut_ptr() as *mut _,
            iov_len: BUFFER_SIZE,
        });

        msgs[i].write(mmsghdr {
            msg_hdr: libc::msghdr {
                msg_name: &mut addr_storage[i] as *mut _ as *mut _,
                msg_namelen: size_of::<sockaddr_in6>() as u32,
                msg_iov: iovecs[i].as_mut_ptr() as *mut _,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            msg_len: 0,
        });
    }

    loop {
        // Receive batch
        let received = unsafe {
            recvmmsg(
                fd,
                msgs[0].as_mut_ptr(),
                BATCH_SIZE as u32,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };

        if received <= 0 {
            // println!("No packets received or error occurred");
            continue;
        }

        // Process packets
        for i in 0..received as usize {
            let len = unsafe { msgs[i].assume_init().msg_len as usize };
            println!("Received packet {} of {} with len {}", i, received, len);
            if len < 28 {
                println!("Packet too short, expected at least 28 bytes, got {}", len);
                continue;
            }

            let buffer = &buffers[i][..len];
            if &buffer[0..4] != b"RP01" {
                println!("prefix did not match");
                continue;
            }
            println!("prefix matched");

            // If a seed is provided, validate the HMAC-SHA256 hash
            if let Some(seed) = &seed {
                // Extract the time from the packet (offset 8, 4 bytes)
                let packet_time = u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]) as u64;
                println!("Received time is {}", packet_time);

                // Get the current time in seconds since UNIX epoch
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                println!("Current time is {}", current_time);

                // Check if the packet time is within the allowed range
                if packet_time > current_time + MAX_TIME_DIFF_EARLY || packet_time < current_time - MAX_TIME_DIFF_LATE {
                    println!("Time check failed");
                    continue; // Discard packets with invalid timestamps
                }
                println!("Time check passed time in hex: {:x}", packet_time);

                // Extract the hash from the packet (offset 12, 16 bytes)
                let packet_hash = &buffer[12..28]; // 128-bit HMAC-SHA256 (16 bytes)

                // Get the source IP from the message header
                let source_ip = unsafe {
                    let addr = &addr_storage[i] as *const _ as *const libc::sockaddr_in6;

                    if (*addr).sin6_family as libc::c_int == libc::AF_INET6 {
                        // Handle IPv6 addresses (this includes mapped IPv4 addresses)
                        let ip_bytes = &(*addr).sin6_addr.s6_addr;

                        // Check if it's an IPv4-mapped IPv6 address
                        if ip_bytes[0..10] == [0u8; 10] && ip_bytes[10] == 0xff && ip_bytes[11] == 0xff {
                            // It's an IPv4-mapped address, print as IPv4
                            format!("{}.{}.{}.{}",
                                    ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]
                            )
                        } else {
                            // Print as a regular IPv6 address
                            format!(
                                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                                (u16::from(ip_bytes[0]) << 8) | u16::from(ip_bytes[1]),
                                (u16::from(ip_bytes[2]) << 8) | u16::from(ip_bytes[3]),
                                (u16::from(ip_bytes[4]) << 8) | u16::from(ip_bytes[5]),
                                (u16::from(ip_bytes[6]) << 8) | u16::from(ip_bytes[7]),
                                (u16::from(ip_bytes[8]) << 8) | u16::from(ip_bytes[9]),
                                (u16::from(ip_bytes[10]) << 8) | u16::from(ip_bytes[11]),
                                (u16::from(ip_bytes[12]) << 8) | u16::from(ip_bytes[13]),
                                (u16::from(ip_bytes[14]) << 8) | u16::from(ip_bytes[15])
                            )
                        }
                    } else {
                        "Unknown address family".to_string()
                    }
                };
                println!("Source IP address: {}", source_ip);

                // Generate the expected HMAC-SHA256 hash using the time from the packet
                let mut mac = HmacSha256::new_from_slice(seed).unwrap();
                mac.update(source_ip.as_bytes());
                mac.update(&packet_time.to_be_bytes());
                let expected_hash_full = mac.finalize().into_bytes();
                let expected_hash = &expected_hash_full[..16]; // Get the first 16 bytes (128 bits)

                // Compare the packet hash with the expected hash
                if packet_hash != expected_hash {
                    println!("Hash check failed");
                    continue; // Ignore packets with invalid hashes
                }
                println!("Hash check passed");
            } else {
                // Fallback to the old "testme" check
                if &buffer[8..14] != b"testme" {
                    continue;
                }
            }

            // Prepare response (RR01 + seq)
            response_buffers[i].copy_from_slice(&[b'R', b'R', b'0', b'1', buffer[4], buffer[5], buffer[6], buffer[7]]);

            // Reuse iovec for sending
            iovecs[i].write(iovec {
                iov_base: response_buffers[i].as_ptr() as *mut _,
                iov_len: 8,
            });

            msgs[i].write(mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &addr_storage[i] as *const _ as *mut _,
                    msg_namelen: size_of::<sockaddr_in6>() as u32,
                    msg_iov: iovecs[i].as_ptr() as *mut _,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 8,
            });
        }

        // Send responses
        unsafe {
            sendmmsg(
                fd,
                msgs[0].as_mut_ptr(),
                received as u32,
                libc::MSG_DONTWAIT,
            );
        }
    }
}