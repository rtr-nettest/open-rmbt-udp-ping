use anyhow::Result;
use libbpf_rs::{Object, Link};
use nix::libc::{if_nametoindex, sysconf, _SC_PAGESIZE};
use std::os::unix::prelude::RawFd;
use std::ptr;

const IFACE: &str = "eth0";
const XDP_PROG_PATH: &str = "xdp-prog/target/bpf/programs/xdp_prog/xdp_prog.elf";

#[tokio::main]
async fn main() -> Result<()> {
    // Load XDP program
    let mut obj = Object::from_file(XDP_PROG_PATH)?;
    let prog = obj.prog("xdp").expect("Program not found");

    // Attach to interface
    let ifindex = unsafe { if_nametoindex(IFACE.as_ptr() as *const _) };
    let link = prog.attach_xdp(ifindex as i32)?;

    // Configure system
    enable_hugepages()?;
    isolate_cpus()?;

    println!("XDP server running on {}", IFACE);
    tokio::signal::ctrl_c().await?;

    link.detach()?;
    Ok(())
}

fn enable_hugepages() -> Result<()> {
    let page_size = unsafe { sysconf(_SC_PAGESIZE) };
    std::fs::write("/proc/sys/vm/nr_hugepages", format!("{}", 1 << 30 / page_size))?;
    Ok(())
}

fn isolate_cpus() -> Result<()> {
    let cores = (0..num_cpus::get_physical()).map(|c| c.to_string()).collect::<Vec<_>>().join(",");
    std::fs::write("/sys/devices/system/cpu/isolated", cores)?;
    Ok(())
}