use std::io;
use std::mem::{size_of, MaybeUninit};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use socket2::{Domain, Protocol, Socket, Type};
use libc::{recvmmsg, sendmmsg, mmsghdr, iovec, sockaddr_in6, ntohs, cpu_set_t, CPU_ZERO, CPU_SET, sched_setaffinity};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use clap::{Arg, App};
use num_cpus;

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
                .help("Number of CPUs to use (default: all available)")
                .takes_value(true),
        )
        .get_matches();

    let seed = matches.value_of("seed").map(|s| s.as_bytes().to_vec());
    let port = 444;

    // Determine number of CPUs to use
    let total_cpus = num_cpus::get();
    let cpus_to_use = matches
        .value_of("cpus")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(total_cpus)
        .min(total_cpus);

    println!("Using {} of {} available CPUs", cpus_to_use, total_cpus);

    let seed = Arc::new(seed);

    // Spawn worker threads
    for cpu in 0..cpus_to_use {
        let seed = seed.clone();
        thread::spawn(move || {
            // Pin thread to specific CPU
            if let Err(e) = pin_thread_to_cpu(cpu) {
                eprintln!("Failed to pin thread to CPU {}: {}", cpu, e);
            }
            worker_thread(port, seed.as_ref().clone()).expect("Worker thread failed");
        });
    }

    println!("Server running on port {} ({} threads)", port, cpus_to_use);
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

fn sockaddr_in6_to_ipv4_string(addr: &sockaddr_in6) -> Option<String> {
    // Extract the IPv6 address components
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

    // Create an `Ipv6Addr` using the extracted segments
    let ipv6_addr = Ipv6Addr::from(segments);

    // Check if the IPv6 address is an IPv4-mapped address
    if let Some(ipv4_addr) = ipv6_addr.to_ipv4() {
        Some(ipv4_addr.to_string())
    } else {
        None
    }
}

fn worker_thread(port: u16, seed: Option<Vec<u8>>) -> io::Result<()> {
    let socket = setup_socket(port)?;
    let fd = socket.as_raw_fd();

    let mut buffers = [[0u8; BUFFER_SIZE]; BATCH_SIZE];
    let mut responses = [[0u8; 8]; BATCH_SIZE];
    let mut addr_storage: [sockaddr_in6; BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut msgs = [MaybeUninit::<mmsghdr>::zeroed(); BATCH_SIZE];
    let mut iovecs = [MaybeUninit::<iovec>::zeroed(); BATCH_SIZE];

    // Initialize static iovec structures
    for i in 0..BATCH_SIZE {
        iovecs[i].write(iovec {
            iov_base: buffers[i].as_mut_ptr() as *mut _,
            iov_len: BUFFER_SIZE,
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

            if len < 32 || &buffer[0..4] != b"RP01" {
                continue;
            }

            let packet_time = u32::from_be_bytes(buffer[8..12].try_into().unwrap()) as u64;
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if packet_time > current_time + MAX_TIME_DIFF_EARLY ||
                packet_time < current_time - MAX_TIME_DIFF_LATE {
                continue;
            }

            if let Some(seed) = &seed {
                let packet_hash = &buffer[12..28];
                let mut mac = HmacSha256::new_from_slice(seed).unwrap();


                mac.update(&packet_time.to_be_bytes());

                if packet_hash != &mac.finalize().into_bytes()[..16] {
                    println!("hmac mismatch");
                    continue;
                }
                println!("hmac matches");
            }


            let src_addr = sockaddr_in6_to_socketaddr_v6(&addr_storage[i]);
            println!("Source address v6: {}", src_addr.ip());


            // TODO: The IP conversion code ugly and incomplete, but it does the job for now
            // in the future the IP comparison shall be based on binary IPv6 addresses only.
            // e.g. [::ffff:40.177.124.111] for an ipv4 address

            // Check for and extract IPv4 address from IPv6 address
            let ipv4_str = if let _ipv6_addr = src_addr.ip() {
                match src_addr.ip().to_ipv4() {
                    Some(ipv4_addr) => ipv4_addr.to_string(),
                    None => format!("{}", src_addr.ip()), // If it's not an IPv4-mapped IPv6, keep as is
                }
            } else {
                // If conversion function gives non-v6 address type, handle accordingly
                format!("{}", src_addr.ip())
            };

            println!("Source address: {}", ipv4_str);

            let mut mac_ip = HmacSha256::new_from_slice(ipv4_str.as_bytes()).unwrap();

            let mut ip_match = false;

            if let Some(seed) = &seed {
                let packet_ip_hash = &buffer[28..32];

                println!("Packet IP hash in hex: {}", hex::encode(packet_ip_hash));
                
                mac_ip.update(&packet_time.to_be_bytes());
                let mac_ip_hash = &mac_ip.finalize().into_bytes()[..4];


                println!("Own IP hash in hex: {}", hex::encode(mac_ip_hash));

                if packet_ip_hash == mac_ip_hash {
                    ip_match = true;
                    println!("hmac_ip matches");
                }
                else {
                    println!("hmac_ip mismatch");
                }

            }

            if ip_match {
                responses[i].copy_from_slice(&[b'R', b'R', b'0', b'1',
                    buffer[4], buffer[5], buffer[6], buffer[7]]);
            }
            else { responses[i].copy_from_slice(&[b'R', b'E', b'0', b'1',
                    buffer[4], buffer[5], buffer[6], buffer[7]]);
            }

            msgs[send_count].write(mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &addr_storage[i] as *const _ as *mut _,
                    msg_namelen: size_of::<sockaddr_in6>() as u32,
                    msg_iov: &iovec {
                        iov_base: responses[i].as_ptr() as *mut _,
                        iov_len: 8,
                    } as *const _ as *mut _,
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

fn pin_thread_to_cpu(cpu: usize) -> io::Result<()> {

    //TODO: Add offset-option, thus not always pin to the first cpus...

    // Check if the CPU number provided is valid.
    // This should normally suit typical use, considering CPU maximization limits.
    if cpu >= num_cpus::get() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("CPU {} exceeds available CPU count {:?}", cpu, num_cpus::get()),
        ));
    }

    // Get the current thread ID
    let tid = unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t };

    // Constructing the cpu_set for desired CPU
    let mut cpuset: cpu_set_t = unsafe { std::mem::zeroed() };

    // Zero out the CPU set
    unsafe { CPU_ZERO(&mut cpuset) };

    // Add the target CPU to our set
    unsafe { CPU_SET(cpu, &mut cpuset) };

    // Attempt to set CPU affinity for the current thread
    let result = unsafe { sched_setaffinity(tid, std::mem::size_of::<cpu_set_t>(), &cpuset) };

    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
