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

    let port = 444;
    let socket = setup_socket(port)?;
    let socket = Arc::new(socket);

    let threads = num_cpus::get();
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

        if received <= 0 { continue; }

        // Process packets
        for i in 0..received as usize {

            let len = unsafe { msgs[i].assume_init().msg_len as usize };
            if len < 14 { continue; }

            let buffer = &buffers[i][..len];
            if &buffer[0..4] != b"RP01" {
                continue;
            }

            // If a seed is provided, validate the HMAC-SHA256 hash
            if let Some(seed) = &seed {
                // Extract the time from the packet (offset 8, 4 bytes)
                let packet_time = u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]) as u64;

                // Get the current time in seconds since UNIX epoch
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                // Check if the packet time is within the allowed range
                if packet_time > current_time + MAX_TIME_DIFF_EARLY || packet_time < current_time - MAX_TIME_DIFF_LATE {
                    continue; // Discard packets with invalid timestamps
                }

                // Extract the hash from the packet (offset 12, 32 bytes)
                let packet_hash = &buffer[12..44]; // HMAC-SHA256 is 32 bytes

                // Get the source IP from the message header
                let source_ip = unsafe {
                    let addr = &addr_storage[i] as *const _ as *const libc::sockaddr_in6;
                    let ip_bytes = &(*addr).sin6_addr.s6_addr;
                    format!(
                        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                        ip_bytes[4], ip_bytes[5], ip_bytes[6], ip_bytes[7]
                    )
                };

                // Generate the expected HMAC-SHA256 hash using the time from the packet
                let mut mac = HmacSha256::new_from_slice(seed).unwrap();
                mac.update(source_ip.as_bytes());
                mac.update(&packet_time.to_be_bytes());
                let expected_hash = mac.finalize().into_bytes();

                // Compare the packet hash with the expected hash
                if packet_hash != expected_hash.as_slice() {
                    continue; // Ignore packets with invalid hashes
                }
            } else {
                // Fallback to the old "testme" check
                if &buffer[8..14] != b"testme" {
                    continue;
                }
            }

            // Prepare response (RR01 + seq)
            let response = [b'R', b'R', b'0', b'1', buffer[4], buffer[5], buffer[6], buffer[7]];

            // Reuse iovec for sending
            iovecs[i].write(iovec {
                iov_base: response.as_ptr() as *mut _,
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