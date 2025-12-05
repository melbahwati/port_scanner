# pscan (rust port scanner)

Simple TCP port scanner CLI written in Rust. Uses `connect_timeout` to detect open ports.
Only scan hosts you own or have explicit permission to test.

## Features
- Target IP or domain
- Port range (ex: 1-1000)
- Timeout per port (default 50ms)
- Optional parallel scanning
- Progress indicator
- Graceful Ctrl+C cancellation
- Service hints for common ports

## Usage

### Help
```bash
cargo run -- --help
