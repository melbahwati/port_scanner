use anyhow::{bail, Result};
use clap::Parser;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use port_scanner::{resolve_target, scan_ip, PortRange};

/// a simple tcp port scanner (authorized targets only).
#[derive(Parser, Debug)]
#[command(
    name = "port_scanner",
    version = "1.0",
    author = "Mo Elbahwati",
    about = "simple tcp port scanner (authorized targets only)"
)]
struct Args {
    #[arg(short = 'H', long, value_name = "HOST")]
    target: String,

    #[arg(short = 'p', long, default_value = "1-1000")]
    ports: PortRange,

    #[arg(short = 't', long, default_value_t = 50)]
    timeout_ms: u64,

    #[arg(long, default_value_t = 0)]
    retries: u8,

    #[arg(long, default_value_t = false)]
    parallel: bool,

    #[arg(long)]
    threads: Option<usize>,

    #[arg(long, default_value_t = false)]
    show_closed: bool,

    #[arg(long, default_value_t = false)]
    all_ips: bool,

    #[arg(long, default_value_t = true)]
    progress: bool,
}

/// small "service hint" list for common ports
fn service_hint(port: u16) -> &'static str {
    match port {
        20 | 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        135 => "msrpc",
        139 => "netbios",
        143 => "imap",
        443 => "https",
        445 => "smb",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgres",
        6379 => "redis",
        8000 => "http-alt",
        8080 => "http-alt",
        8443 => "https-alt",
        _ => "",
    }
}

fn print_results(ip: std::net::IpAddr, results: &[port_scanner::ScanResult], show_closed: bool) {
    println!();
    println!("target ip: {ip}");
    println!("{:<8}  {:<6}  {}", "port", "state", "hint");
    println!("{:-<8}  {:-<6}  {:-<8}", "", "", "");

    let mut open_count = 0;

    for r in results {
        let state = if r.open { "open" } else { "closed" };
        if r.open {
            open_count += 1;
        }

        if show_closed || r.open {
            println!("{:<8}  {:<6}  {}", r.port, state, service_hint(r.port));
        }
    }

    println!();
    println!("open ports found: {open_count}");
}

fn start_progress_line(
    total: usize,
    scanned: Arc<AtomicUsize>,
    done: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    started: Instant,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !done.load(Ordering::Relaxed) && !cancelled.load(Ordering::Relaxed) {
            let n = scanned.load(Ordering::Relaxed);
            let pct = if total == 0 {
                100.0
            } else {
                (n as f64 / total as f64) * 100.0
            };

            eprint!(
                "\rscanning... {n}/{total} ({pct:.1}%) elapsed: {:?}",
                started.elapsed()
            );
            let _ = io::stderr().flush();
            std::thread::sleep(Duration::from_millis(200));
        }
        eprintln!();
    })
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.timeout_ms == 0 {
        bail!("timeout must be at least 1 ms");
    }
    let timeout = Duration::from_millis(args.timeout_ms);

    let default_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let threads = args.threads.unwrap_or(default_threads).max(1);

    let ips = resolve_target(&args.target)?;
    let ips_to_scan = if args.all_ips { ips } else { vec![ips[0]] };

    let ports = args.ports.to_vec();

    let cancelled = Arc::new(AtomicBool::new(false));
    {
        let cancelled = cancelled.clone();
        ctrlc::set_handler(move || {
            cancelled.store(true, Ordering::SeqCst);
        })?;
    }

    println!("pscan");
    println!("  target      : {}", args.target);
    println!("  ips scanned  : {}", ips_to_scan.len());
    println!("  ports        : {}-{}", args.ports.start, args.ports.end);
    println!("  timeout      : {} ms", args.timeout_ms);
    println!("  retries      : {}", args.retries);
    println!("  parallel     : {}", args.parallel);
    if args.parallel {
        println!("  threads      : {}", threads);
    }
    println!("  show_closed  : {}", args.show_closed);

    for ip in ips_to_scan {
        let started = Instant::now();

        let scanned = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicBool::new(false));

        let progress_handle = if args.progress {
            Some(start_progress_line(
                ports.len(),
                scanned.clone(),
                done.clone(),
                cancelled.clone(),
                started,
            ))
        } else {
            None
        };

        let results = scan_ip(
            ip,
            &ports,
            timeout,
            args.retries,
            args.parallel,
            threads,
            if args.progress {
                Some(scanned.clone())
            } else {
                None
            },
            cancelled.clone(),
        );

        done.store(true, Ordering::Relaxed);
        if let Some(h) = progress_handle {
            let _ = h.join();
        }

        if cancelled.load(Ordering::Relaxed) {
            eprintln!("scan cancelled (results may be incomplete)");
        } else {
            eprintln!("scan complete in {:?}", started.elapsed());
        }

        print_results(ip, &results, args.show_closed);

        if cancelled.load(Ordering::Relaxed) {
            return Ok(());
        }
    }

    Ok(())
}
