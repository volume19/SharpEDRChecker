//! Directory enumeration and EDR detection
//!
//! Scans common installation directories for EDR/AV product presence.

use crate::edr_data::find_matches;
use crate::error::DirectoryError;
use std::fmt;
use std::fs;
use std::path::PathBuf;

/// A detection of an EDR/AV product in a directory
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// Path to the detected directory
    pub path: PathBuf,
    /// List of EDR signatures that matched
    pub matches: Vec<&'static str>,
}

/// Result of directory checking operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    /// List of detections found
    pub detections: Vec<Detection>,
}

impl CheckResult {
    /// Create a new empty check result
    pub fn new() -> Self {
        Self {
            detections: Vec::new(),
        }
    }

    /// Returns true if any detections were found
    pub fn has_detections(&self) -> bool {
        !self.detections.is_empty()
    }

    /// Returns the number of detections
    pub fn count(&self) -> usize {
        self.detections.len()
    }
}

impl Default for CheckResult {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detections.is_empty() {
            write!(f, "[+] No suspicious directories found")
        } else {
            writeln!(f, "[!] Directory Summary:")?;
            for detection in &self.detections {
                writeln!(
                    f,
                    "\t[-] {} : {}",
                    detection.path.display(),
                    detection.matches.join(", ")
                )?;
            }
            Ok(())
        }
    }
}

/// Check common installation directories for EDR/AV products
///
/// Scans the following directories on Windows:
/// - C:\Program Files
/// - C:\Program Files (x86)
/// - C:\ProgramData
///
/// On non-Windows platforms, returns an empty result.
///
/// # Returns
///
/// * `Ok(CheckResult)` - Detection results (may be empty)
/// * `Err(DirectoryError)` - If a critical error occurs during scanning
///
/// # Example
///
/// ```no_run
/// use sharp_edr_checker::directory::check_directories;
///
/// match check_directories() {
///     Ok(result) => {
///         if result.has_detections() {
///             println!("Found {} suspicious directories", result.count());
///             println!("{}", result);
///         }
///     }
///     Err(e) => eprintln!("Error checking directories: {}", e),
/// }
/// ```
pub fn check_directories() -> Result<CheckResult, DirectoryError> {
    let mut result = CheckResult::new();

    #[cfg(windows)]
    let base_dirs = vec![
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\ProgramData",
    ];

    #[cfg(not(windows))]
    let base_dirs: Vec<&str> = vec![];

    for base_dir in base_dirs {
        match enumerate_and_check_directory(base_dir) {
            Ok(detections) => result.detections.extend(detections),
            Err(e) => {
                // Log the error but continue with other directories
                eprintln!("Warning: Failed to check directory {}: {}", base_dir, e);
            }
        }
    }

    Ok(result)
}

/// Enumerate subdirectories and check for EDR matches
fn enumerate_and_check_directory(base_path: &str) -> Result<Vec<Detection>, DirectoryError> {
    let mut detections = Vec::new();

    // Read directory entries
    let entries = match fs::read_dir(base_path) {
        Ok(entries) => entries,
        Err(e) => {
            // If we can't read the directory (permission denied, doesn't exist, etc.),
            // return an error
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                return Err(DirectoryError::AccessDenied {
                    path: base_path.to_string(),
                });
            }
            return Err(DirectoryError::Io(e));
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue, // Skip entries we can't read
        };

        // Only process directories
        if let Ok(metadata) = entry.metadata() {
            if !metadata.is_dir() {
                continue;
            }
        }

        let path = entry.path();

        // Check if the directory path matches any EDR signatures
        if let Some(path_str) = path.to_str() {
            let matches = find_matches(path_str);
            if !matches.is_empty() {
                detections.push(Detection {
                    path: path.clone(),
                    matches,
                });
            }
        }
    }

    Ok(detections)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_result_empty() {
        let result = CheckResult::new();
        assert!(!result.has_detections());
        assert_eq!(result.count(), 0);
        assert_eq!(result.to_string(), "[+] No suspicious directories found");
    }

    #[test]
    fn test_check_result_with_detections() {
        let mut result = CheckResult::new();
        result.detections.push(Detection {
            path: PathBuf::from("C:\\Program Files\\CrowdStrike"),
            matches: vec!["crowdstrike"],
        });

        assert!(result.has_detections());
        assert_eq!(result.count(), 1);

        let output = result.to_string();
        assert!(output.contains("Directory Summary"));
        assert!(output.contains("CrowdStrike"));
        assert!(output.contains("crowdstrike"));
    }

    #[test]
    fn test_detection_equality() {
        let det1 = Detection {
            path: PathBuf::from("/test/path"),
            matches: vec!["test"],
        };
        let det2 = Detection {
            path: PathBuf::from("/test/path"),
            matches: vec!["test"],
        };
        assert_eq!(det1, det2);
    }

    #[test]
    #[cfg(windows)]
    fn test_check_directories_runs_without_panic() {
        // This test just ensures the function doesn't panic
        // It may or may not find detections depending on the system
        let result = check_directories();
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(not(windows))]
    fn test_check_directories_empty_on_non_windows() {
        let result = check_directories().unwrap();
        assert_eq!(result.count(), 0);
    }
}
