use anyhow::{Context, Result};
use libbpf_rs::{Object, Link};
use nix::libc::{if_nametoindex};
use std::ffi::CString;
use std::os::unix::prelude::OsStrExt;
use std::path::Path;
use tokio::signal;

const IFACE: &str = "eth0";
const XDP_PROG_PATH: &str = "xdp-prog/target/bpf/programs/xdp_prog/xdp_prog.elf";

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Load XDP object file
    let mut obj = Object::from_file(XDP_PROG_PATH)
        .context("Failed to load XDP object file")?;

    // 2. Get XDP program handle
    let prog = obj.prog("xdp")
        .context("XDP program 'xdp' not found in object file")?;

    // 3. Convert interface name to index
    let ifname = CString::new(IFACE)
        .context("Invalid interface name")?;
    let ifindex = unsafe { if_nametoindex(ifname.as_ptr()) };
    if ifindex == 0 {
        return Err(std::io::Error::last_os_error())
            .context("Failed to get interface index")?;
    }

    // 4. Attach XDP program
    let _link = Link::from(prog.attach_xdp(ifindex as i32)
        .context("Failed to attach XDP program")?);

    // 5. System configuration
    enable_hugepages()
        .context("Failed to enable hugepages")?;
    isolate_cpus()
        .context("Failed to isolate CPUs")?;

    println!("XDP server running on interface {}", IFACE);
    println!("Press Ctrl+C to exit...");

    // 6. Wait for termination signal
    signal::ctrl_c().await?;
    println!("Detaching XDP program...");

    Ok(())
}

fn enable_hugepages() -> Result<()> {
    let hugepage_size: u64 = 1 << 30; // 1GB hugepages
    let nr_hugepages = (hugepage_size / sysconf::page_size())?;

    std::fs::write(
        "/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages",
        nr_hugepages.to_string()
    ).map_err(|e| e.into())
}

fn isolate_cpus() -> Result<()> {
    let cores = (0..num_cpus::get_physical())
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(",");

    std::fs::write("/sys/devices/system/cpu/isolated", cores)
        .map_err(|e| e.into())
}

// Helper module for safe sysconf access
mod sysconf {
    use nix::libc::{sysconf, _SC_PAGESIZE};

    pub fn page_size() -> nix::Result<u64> {
        let size = unsafe { sysconf(_SC_PAGESIZE) };
        if size == -1 {
            Err(nix::Error::last())
        } else {
            Ok(size as u64)
        }
    }
}