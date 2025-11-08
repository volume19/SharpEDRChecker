//! SharpEDRChecker - Rust Port
//!
//! EDR/AV/logging tool detection for authorized security assessments.
//!
//! # Purpose
//!
//! This is a DEFENSIVE security tool for authorized penetration testing.
//! It enumerates security products to understand defensive posture during
//! legitimate security assessments with explicit permission.
//!
//! # Architecture
//!
//! - `edr_data`: Static signatures for EDR/AV product detection
//! - `error`: Custom error types for all modules
//! - `privilege`: Admin/privilege level detection
//! - `file_info`: PE file metadata extraction
//! - `directory`: Directory enumeration and matching
//! - `service`: Windows service enumeration via WMI
//! - `process`: Process enumeration and module checking
//! - `driver`: Kernel driver enumeration
//! - `registry`: Registry checking (stub)

#![warn(missing_docs)]
#![warn(clippy::all)]
#![deny(unsafe_op_in_unsafe_fn)]

// Module declarations - will be implemented incrementally
pub mod directory;
pub mod driver;
pub mod edr_data;
pub mod error;
pub mod file_info;
pub mod privilege;
pub mod process;
pub mod registry;
pub mod service;
