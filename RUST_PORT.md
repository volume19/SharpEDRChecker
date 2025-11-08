# Rust Port of SharpEDRChecker

This directory contains the idiomatic Rust port of SharpEDRChecker, maintaining full functional parity with the original C# version while adding type safety, memory safety, and cross-platform compilation.

## Purpose

**⚠️ DEFENSIVE SECURITY TOOL FOR AUTHORIZED USE ONLY ⚠️**

This tool is designed for **authorized penetration testing and red team operations**. It enumerates EDR/AV/logging products to assess defensive posture during legitimate security assessments **with explicit permission**.

### Intended Use Cases
- Authorized penetration testing engagements
- Red team exercises with organizational approval
- Security posture assessments
- Defensive security research and blue team validation

### NOT Intended For
- Evasion or bypassing security controls
- Unauthorized system access
- Malware development or deployment
- Anti-forensics or detection avoidance
- Any illegal or unauthorized activities

**You must obtain proper authorization before running this tool on any system.**

## Architecture

The Rust port is organized into focused modules:

- **`edr_data`** - Static EDR/AV signature database (132 signatures)
- **`error`** - Type-safe error handling with `thiserror`
- **`privilege`** - Administrator/elevation detection via Windows token APIs
- **`file_info`** - PE file version metadata extraction
- **`directory`** - Program Files/ProgramData directory scanning
- **`service`** - Windows service enumeration via WMI
- **`process`** - Running process enumeration and module checking
- **`driver`** - Kernel driver enumeration via psapi.dll
- **`registry`** - Registry checking (stub, not yet implemented)

## Building

### Prerequisites

- **Rust 1.70+** (install from https://rustup.rs/)
- **Windows SDK** (for Windows builds with `windows-sys` crate)

### Build Commands

```bash
# Development build
cargo build

# Release build (optimized, stripped)
cargo build --release

# Cross-compile for Windows (from Linux, requires mingw-w64)
cargo build --release --target x86_64-pc-windows-gnu
```

### Build Targets

- **Primary**: `x86_64-pc-windows-msvc` (native Windows)
- **Secondary**: `x86_64-unknown-linux-gnu` (graceful degradation, limited functionality)

## Testing

```bash
# Run all unit tests
cargo test --workspace

# Run tests with output
cargo test --workspace -- --nocapture

# Run specific module tests
cargo test --lib edr_data
cargo test --lib process

# Check code quality
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# Security audit
cargo install cargo-audit
cargo audit
```

### Test Coverage

- **30+ unit tests** covering all modules
- Platform-specific tests with `#[cfg(windows)]` guards
- Error handling and edge case validation
- Cross-platform graceful degradation tests

## Running

```bash
# Run development build
cargo run

# Run release build
cargo run --release

# Run pre-built binary
./target/release/sharp_edr_checker
```

### Expected Output

On Windows with admin privileges:
```
##################################################################
   [!][!][!] Welcome to SharpEDRChecker by @PwnDexter [!][!][!]
[+][+][+] Running as admin, all checks will be performed [+][+][+]
##################################################################

######################################
[!][!][!] Checking processes [!][!][!]
######################################
...
```

On Linux or without Windows:
```
Warning: Could not check privilege level: Privilege checking not supported on this platform
...
[-] Error checking processes: WMI query failed: Process enumeration not supported on this platform
...
```

## Dependencies

All dependencies are from trusted, well-maintained sources:

| Crate | Version | Purpose | License | Trust |
|-------|---------|---------|---------|-------|
| `thiserror` | 1.0 | Error derive macros | MIT/Apache-2.0 | ⭐ Very High (dtolnay) |
| `windows-sys` | 0.59 | Windows API bindings | MIT/Apache-2.0 | ⭐ Very High (Microsoft) |
| `wmi` | 0.13 | WMI query interface | MIT/Apache-2.0 | ⭐ High (community) |
| `tempfile` | 3.10 | Test fixtures (dev) | MIT/Apache-2.0 | ⭐ Very High |

Run `cargo audit` regularly to check for known vulnerabilities.

## Differences from C# Version

### Improvements

1. **Type Safety**: Strongly typed errors instead of generic exceptions
2. **Memory Safety**: No null pointers, buffer overflows, or data races
3. **Structured Output**: Returns typed data structures instead of pre-formatted strings
4. **Cross-Platform**: Compiles on Linux with graceful feature degradation
5. **No Runtime**: Single static binary, no .NET Framework dependency
6. **RAII Handles**: Automatic resource cleanup (handles, COM objects)
7. **Zero-Cost Abstractions**: Performance equivalent to C with safety guarantees

### Functional Parity

| Feature | C# | Rust | Status |
|---------|-----|------|--------|
| Process enumeration | ✅ WMI | ✅ WMI | ✅ Parity |
| Module checking | ✅ ProcessModule | ✅ Toolhelp32 | ✅ Parity |
| Service enumeration | ✅ WMI | ✅ WMI | ✅ Parity |
| Driver enumeration | ✅ psapi P/Invoke | ✅ psapi FFI | ✅ Parity |
| Directory scanning | ✅ System.IO | ✅ std::fs | ✅ Parity |
| File metadata | ✅ FileVersionInfo | ✅ GetFileVersionInfo | ✅ Parity |
| Privilege check | ✅ WindowsIdentity | ✅ GetTokenInformation | ✅ Parity |
| Registry check | ⚠️ Stub | ⚠️ Stub | ✅ Parity |

### Known Limitations

- **Windows-only Features**: WMI, driver enumeration, and file version info require Windows
- **Unicode**: UTF-16 handling may differ slightly from .NET culture-invariant operations
- **Registry**: Not yet implemented (matches C# stub)

## Security Considerations

### Safe Use of Unsafe Code

The Rust port uses `unsafe` blocks only where necessary for FFI:

1. **Windows API calls**: `privilege.rs`, `file_info.rs`, `process.rs`, `driver.rs`
2. **Safety invariants**: All `unsafe` blocks have documented safety contracts
3. **RAII guards**: Handles are automatically closed via `Drop` trait
4. **No buffer overruns**: Buffer sizes validated before FFI calls
5. **Denied unsafe ops**: `#![deny(unsafe_op_in_unsafe_fn)]` enforces explicit safety

### Least Privilege

- Runs as **normal user** by default (admin not required)
- Admin privileges enable full driver/process enumeration
- **Read-only operations** - no system modifications
- No credential harvesting, code injection, or exploitation features

### Logging & Auditability

- All enumeration actions printed to stdout (audit trail)
- Errors logged to stderr
- No stealth or anti-forensics capabilities
- Designed for transparent, authorized assessment

## Continuous Integration

GitHub Actions workflow (`.github/workflows/rust-ci.yml`):

- ✅ **Linux**: Build, test, clippy, formatting
- ✅ **Windows**: Build, test, functional smoke test
- ✅ **Security audit**: `cargo audit` for CVE detection

## Release Artifacts

Release builds are optimized with:

```toml
[profile.release]
strip = true          # Remove debug symbols
lto = true            # Link-time optimization
codegen-units = 1     # Maximum optimization
panic = "abort"       # Smaller binary, no unwinding
```

Produces a single ~1.5MB static binary (no DLLs required except system libraries).

## License

MIT License (same as original SharpEDRChecker)

## Credits

- **Original Author**: [@PwnDexter](https://twitter.com/PwnDexter)
- **Rust Port**: Authorized port maintaining defensive-only capabilities
- **Blog Post**: https://redteaming.co.uk/2021/03/18/sharpedrchecker/

## Disclaimer

This tool is provided for **authorized security testing only**. Unauthorized use may violate computer fraud and abuse laws (CFAA in the US, Computer Misuse Act in the UK, etc.). The authors and contributors are not responsible for misuse. Always obtain written authorization before using this tool on systems you do not own.
