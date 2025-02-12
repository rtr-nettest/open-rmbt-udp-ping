use std::io;
use std::mem::{size_of, MaybeUninit};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use socket2::{Domain, Protocol, Socket, Type};
use libc::{recvmmsg, sendmmsg, mmsghdr, iovec, sockaddr_in6, ntohs};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use clap::{Arg, App};
use core_affinity::{CoreId, get_core_ids};
use log::{debug, error, info};

const BATCH_SIZE: usize = 64;
const BUFFER_SIZE: usize = 1024;
const MAX_TIME_DIFF_EARLY: u64 = 10;
const MAX_TIME_DIFF_LATE: u64 = 4 * 60 * 60;

type HmacSha256 = Hmac<Sha256>;

fn main() {
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
        .arg(
            Arg::with_name("cpus")
                .short("c")
                .long("cpus")
                .value_name("CPUS")
                .help("CPU cores to use (e.g. 5-8 or 5,6,7,8)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("debug")
                .short("d")
                .long("debug")
                .help("Enable debug logging"),
        )
        .get_matches();

    // Initialize logging
    if matches.is_present("debug") {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
        debug!("Debug logging enabled");
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    let seed = matches.value_of("seed").map(|s| s.as_bytes().to_vec());
    let port = 444;

    // Parse CPU list
    let cores = parse_cpu_list(matches.value_of("cpus")).unwrap_or_else(|| {
        get_core_ids().unwrap_or_else(|| {
            error!("Failed to get core IDs");
            std::process::exit(1);
        })
    });

    if cores.is_empty() {
        info!("Using CPU cores: {:?}", cores.iter().map(|c| c.id).collect::<Vec<_>>());
        std::process::exit(1);
    }

    info!("Using CPU cores: {:?}", cores.iter().map(|c| c.id).collect::<Vec<_>>());

    let seed = Arc::new(seed);

    // Spawn worker threads
    for (idx, core_id) in cores.iter().enumerate() {
        let seed = seed.clone();
        let core = *core_id;
        thread::spawn(move || {
            // Pin thread to specific core
            if core_affinity::set_for_current(core) {
                debug!("Worker {} pinned to CPU {}", idx, core.id);
            } else {
                error!("Failed to pin worker {} to CPU {}", idx, core.id);
            }
            worker_thread(port, seed.as_ref().clone()).expect("Worker thread failed");
        });
    }

    info!("Server running on port {} ({} threads)", port, cores.len());
    thread::park()
}


fn sockaddr_in6_to_socketaddr_v6(addr: &sockaddr_in6) -> SocketAddrV6 {
    // Convert the `in6_addr` to an array of 16-bit segments
    let ip_bytes = &addr.sin6_addr.s6_addr;
    let segments = [
        u16::from_be_bytes([ip_bytes[0], ip_bytes[1]]),
        u16::from_be_bytes([ip_bytes[2], ip_bytes[3]]),
        u16::from_be_bytes([ip_bytes[4], ip_bytes[5]]),
        u16::from_be_bytes([ip_bytes[6], ip_bytes[7]]),
        u16::from_be_bytes([ip_bytes[8], ip_bytes[9]]),
        u16::from_be_bytes([ip_bytes[10], ip_bytes[11]]),
        u16::from_be_bytes([ip_bytes[12], ip_bytes[13]]),
        u16::from_be_bytes([ip_bytes[14], ip_bytes[15]]),
    ];

    // Create an `Ipv6Addr` from the segments
    let ipv6_addr = Ipv6Addr::from(segments);

    // Convert the port from network-byte order to host-byte order
    let port = ntohs(addr.sin6_port);

    // Create a `SocketAddrV6` using the extracted information
    SocketAddrV6::new(ipv6_addr, port, addr.sin6_flowinfo, addr.sin6_scope_id)
}


fn worker_thread(port: u16, seed: Option<Vec<u8>>) -> io::Result<()> {
    let socket = setup_socket(port)?;
    let fd = socket.as_raw_fd();

    let mut buffers = [[0u8; BUFFER_SIZE]; BATCH_SIZE];
    let mut responses = [[0u8; 8]; BATCH_SIZE];
    let mut addr_storage: [sockaddr_in6; BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut msgs = [MaybeUninit::<mmsghdr>::zeroed(); BATCH_SIZE];
    let mut iovecs = [MaybeUninit::<iovec>::zeroed(); BATCH_SIZE];
    let mut send_iovecs = [MaybeUninit::<iovec>::zeroed(); BATCH_SIZE]; // Add this line

    // Initialize static iovec structures for receiving
    for i in 0..BATCH_SIZE {
        iovecs[i].write(iovec {
            iov_base: buffers[i].as_mut_ptr() as *mut _,
            iov_len: BUFFER_SIZE,
        });
        // Initialize send_iovecs
        send_iovecs[i].write(iovec {
            iov_base: responses[i].as_mut_ptr() as *mut _,
            iov_len: 8,
        });
    }

    loop {
        let mut msgvec = [MaybeUninit::<mmsghdr>::zeroed(); BATCH_SIZE];
        for i in 0..BATCH_SIZE {
            msgvec[i].write(mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &mut addr_storage[i] as *mut _ as *mut _,
                    msg_namelen: size_of::<sockaddr_in6>() as u32,
                    msg_iov: iovecs[i].as_ptr() as *mut _,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            });
        }

        let received = unsafe {
            recvmmsg(
                fd,
                msgvec[0].as_mut_ptr(),
                BATCH_SIZE as u32,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };

        if received <= 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
            continue;
        }

        let mut send_count = 0;
        for i in 0..received as usize {
            let len = unsafe { msgvec[i].assume_init().msg_len as usize };
            let buffer = &buffers[i][..len];
            debug!("Received (len={}): {}", len, hex::encode(buffer));

            if len != 24 || &buffer[0..4] != b"RP01" {
                continue;
            }

            let packet_time = u32::from_be_bytes(buffer[8..12].try_into().unwrap()) as u64;
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if packet_time > current_time + MAX_TIME_DIFF_EARLY ||
                packet_time < current_time - MAX_TIME_DIFF_LATE {
                debug!("Packet time out of range");
                continue;
            }

            if let Some(seed) = &seed {
                let packet_hash = &buffer[12..20];
                let mut mac = HmacSha256::new_from_slice(seed).unwrap();
                mac.update(&packet_time.to_be_bytes());
                debug!("HMAC packet: {}", hex::encode(packet_hash));                

                if packet_hash != &mac.finalize().into_bytes()[..8] {
                    debug!("HMAC packet mismatch");
                    continue;
                }
                debug!("HMAC packet matches");
            }
            
            let src_addr = sockaddr_in6_to_socketaddr_v6(&addr_storage[i]);
            let src_addr_u128 = src_addr.ip().to_bits();
            debug!("Source address: {} in hex {:032x}", src_addr.ip(), src_addr.ip().to_bits());

            let mut mac_ip = HmacSha256::new_from_slice(&src_addr_u128.to_be_bytes()).unwrap();

            let mut ip_match = false;

            if let Some(_seed) = &seed {
                let packet_ip_hash = &buffer[20..24];
                debug!("HMAC IP: {}", hex::encode(packet_ip_hash));

                mac_ip.update(&packet_time.to_be_bytes());
                let mac_ip_hash = &mac_ip.finalize().into_bytes()[..4];
                debug!("Own HMAC IP: {}", hex::encode(mac_ip_hash));


                if packet_ip_hash == mac_ip_hash {
                    ip_match = true;
                    debug!("HMAC IP matches");
                } else {
                    debug!("HMAC IP mismatch");
                }
            }

            if ip_match {

                responses[i].copy_from_slice(&[b'R', b'R', b'0', b'1',
                    buffer[4], buffer[5], buffer[6], buffer[7]]);
            } else {
                responses[i].copy_from_slice(&[b'R', b'E', b'0', b'1',
                    buffer[4], buffer[5], buffer[6], buffer[7]]);
            }
            debug!("Sending response: {}", hex::encode(responses[i]));
            
            // Use the pre-initialized send_iovecs[i] instead of a temporary iovec
            msgs[send_count].write(mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &addr_storage[i] as *const _ as *mut _,
                    msg_namelen: size_of::<sockaddr_in6>() as u32,
                    msg_iov: send_iovecs[i].as_ptr() as *mut _,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 8,
            });
            send_count += 1;
        }

        if send_count > 0 {
            unsafe {
                sendmmsg(
                    fd,
                    msgs[0].as_mut_ptr(),
                    send_count as u32,
                    libc::MSG_DONTWAIT,
                );
            }
        }
    }
}

fn setup_socket(port: u16) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;  // Critical for multi-core
    socket.set_nonblocking(true)?;
    socket.bind(&format!("[::]:{}", port).parse::<SocketAddr>().unwrap().into())?;
    Ok(socket)
}

    fn parse_cpu_list(cpu_str: Option<&str>) -> Option<Vec<CoreId>> {
        let all_cores = get_core_ids()?;
        let cpu_str = cpu_str?;

        let mut cores = Vec::new();
        for part in cpu_str.split(',') {
            if let Some((start_str, end_str)) = part.split_once('-') {
                let start = start_str.parse::<usize>().ok()?;
                let end = end_str.parse::<usize>().ok()?;
                for id in start..=end {
                    if let Some(core) = all_cores.iter().find(|c| c.id == id) {
                        cores.push(*core);
                    }
                }
            } else {
                let id = part.parse::<usize>().ok()?;
                if let Some(core) = all_cores.iter().find(|c| c.id == id) {
                    cores.push(*core);
                }
            }
        }

        cores.sort();
        cores.dedup();
        Some(cores)
    }
    
    
