# port_scanner (rust port scanner)

Simple TCP port scanner CLI written in Rust. Uses `connect_timeout` to detect open ports.
Only scan hosts you own or have explicit permission to test.

## features
- Target IP or domain
- Port range (ex: 1-1000)
- Timeout per port (default 50ms)
- Optional parallel scanning
- Progress indicator
- Graceful Ctrl+C cancellation
- Service hints for common ports

### help/commands
```bash
cargo run -- --help

## test
cargo test

## scan localhost
cargo run -- --target 127.0.0.1 --ports 1-1000 --parallel

## custom timeout 
cargo run -- --target 127.0.0.1 --ports 1-1000 --timeout-ms 100 --parallel

## show closed ports (warning: noisy)
cargo run -- --target 127.0.0.1 --ports 1-50 --show-closed



