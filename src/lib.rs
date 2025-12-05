use anyhow::{bail, Context, Result};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// represents a port range like 1-1000
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    /// expand the range into a vector of ports to scan
    pub fn to_vec(self) -> Vec<u16> {
        (self.start..=self.end).collect()
    }
}

/// parse `PortRange` from a string like "1-1000"
impl FromStr for PortRange {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            return Err("ports must be in format start-end (example: 1-1000)".to_string());
        }

        let start: u16 = parts[0]
            .trim()
            .parse()
            .map_err(|_| "start port must be a number".to_string())?;

        let end: u16 = parts[1]
            .trim()
            .parse()
            .map_err(|_| "end port must be a number".to_string())?;

        if start == 0 || end == 0 {
            return Err("port range must be between 1 and 65535".to_string());
        }
        if start > end {
            return Err("start port must be <= end port".to_string());
        }

        Ok(PortRange { start, end })
    }
}

/// status for one scanned port
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub port: u16,
    pub open: bool,
}

/// resolve a target (ip or domain) into one or more ip addresses
pub fn resolve_target(target: &str) -> Result<Vec<IpAddr>> {
    let addrs = (target, 0)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve target '{target}'"))?;

    let mut ips = BTreeSet::new();
    for addr in addrs {
        ips.insert(addr.ip());
    }

    if ips.is_empty() {
        bail!("no ip addresses found for target '{target}'");
    }

    Ok(ips.into_iter().collect())
}

/// try to connect to (ip, port) with a timeout.
/// any error is treated as "not open".
pub fn probe_port(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    retries: u8,
    cancelled: &AtomicBool,
) -> bool {
    if cancelled.load(Ordering::Relaxed) {
        return false;
    }

    let addr = SocketAddr::new(ip, port);
    let attempts = retries as usize + 1;

    for _ in 0..attempts {
        if cancelled.load(Ordering::Relaxed) {
            return false;
        }

        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return true;
        }
    }

    false
}

/// scan a list of ports on one ip.
pub fn scan_ip(
    ip: IpAddr,
    ports: &[u16],
    timeout: Duration,
    retries: u8,
    parallel: bool,
    threads: usize,
    progress_counter: Option<Arc<AtomicUsize>>,
    cancelled: Arc<AtomicBool>,
) -> Vec<ScanResult> {
    let mut results = if parallel {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("failed to build rayon thread pool");

        pool.install(|| {
            let progress_counter = progress_counter.clone();
            ports
                .par_iter()
                .map(|&port| {
                    let open = if cancelled.load(Ordering::Relaxed) {
                        false
                    } else {
                        probe_port(ip, port, timeout, retries, &cancelled)
                    };

                    if let Some(p) = &progress_counter {
                        p.fetch_add(1, Ordering::Relaxed);
                    }

                    ScanResult { port, open }
                })
                .collect::<Vec<_>>()
        })
    } else {
        ports
            .iter()
            .map(|&port| {
                let open = probe_port(ip, port, timeout, retries, &cancelled);

                if let Some(p) = &progress_counter {
                    p.fetch_add(1, Ordering::Relaxed);
                }

                ScanResult { port, open }
            })
            .collect::<Vec<_>>()
    };

    results.sort_by_key(|r| r.port);
    results
}
