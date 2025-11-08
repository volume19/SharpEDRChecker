# SharpEDRChecker - Rust Port

Idiomatic Rust port of [SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker) for authorized security assessments.

## Purpose

**DEFENSIVE SECURITY TOOL ONLY** - This tool enumerates EDR/AV/logging products on Windows systems during **authorized penetration testing and red team operations**. It is designed for security professionals conducting legitimate assessments with explicit permission.

### Intended Use
- Authorized penetration testing engagements
- Red team exercises with organizational approval
- Security posture assessment
- Defensive security research

### NOT Intended For
- Evasion or bypassing security controls
- Unauthorized system access
- Malware development or deployment
- Anti-forensics or stealth operations

## Build Instructions

### Windows (Primary Target)
```bash
# Build release binary
cargo build --release --target x86_64-pc-windows-msvc

# Run
cargo run --release
```

### Linux (Limited Functionality)
```bash
# Build (graceful degradation - Windows-specific features disabled)
cargo build --release --target x86_64-unknown-linux-gnu

# Note: WMI and Windows API checks will not function on Linux
```

## Testing
```bash
# Run all tests
cargo test --workspace

# Run with output
cargo test --workspace -- --nocapture

# Lint
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# Security audit
cargo audit
```

## Dependencies

All dependencies are from trusted sources:
- `thiserror` (1.0) - Error handling (dtolnay, MIT/Apache-2.0)
- `windows-sys` (0.59) - Windows API bindings (Microsoft, MIT/Apache-2.0)
- `wmi` (0.13) - WMI queries (community, MIT/Apache-2.0)

Run `cargo audit` regularly to check for vulnerabilities.

## License

MIT License - see LICENSE file

## Disclaimer

This tool is provided for authorized security testing only. Users must obtain proper authorization before running this tool on any system. Unauthorized use may violate computer fraud and abuse laws.
