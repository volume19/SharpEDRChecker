//! Kernel driver enumeration and EDR detection
//!
//! Enumerates loaded kernel drivers using psapi.dll and checks for EDR/AV drivers.

#[cfg(windows)]
use crate::edr_data::find_matches;
use crate::error::DriverError;
#[cfg(windows)]
use crate::file_info;
use serde::Serialize;
use std::fmt;

/// Detection of an EDR/AV product in a kernel driver
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DriverDetection {
    /// Driver base name (e.g., "csagent.sys")
    pub base_name: String,
    /// Full driver file path
    pub file_path: String,
    /// File metadata from the driver binary
    pub file_metadata: Option<String>,
    /// Matched EDR signatures
    pub matches: Vec<&'static str>,
}

/// Result of driver checking operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    /// List of driver detections found
    pub detections: Vec<DriverDetection>,
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
            write!(f, "[+] No suspicious drivers found")
        } else {
            writeln!(f, "[!] Driver Summary:")?;
            for detection in &self.detections {
                writeln!(
                    f,
                    "\t[-] {} : {}",
                    detection.base_name,
                    detection.matches.join(", ")
                )?;
            }
            Ok(())
        }
    }
}

/// Check loaded kernel drivers for EDR/AV products
///
/// Enumerates all loaded kernel drivers using the psapi.dll EnumDeviceDrivers API
/// and checks their metadata against EDR signatures.
///
/// **Requires administrator privileges** for full enumeration.
///
/// # Returns
///
/// * `Ok(CheckResult)` - Detection results (may be empty)
/// * `Err(DriverError)` - If driver enumeration fails
///
/// # Example
///
/// ```no_run
/// use sharp_edr_checker::driver::check_drivers;
///
/// match check_drivers() {
///     Ok(result) => {
///         if result.has_detections() {
///             println!("{}", result);
///         }
///     }
///     Err(e) => eprintln!("Error checking drivers: {}", e),
/// }
/// ```
#[cfg(windows)]
pub fn check_drivers() -> Result<CheckResult, DriverError> {
    use std::mem;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::ProcessStatus::{
        EnumDeviceDrivers, GetDeviceDriverBaseNameW, GetDeviceDriverFileNameW,
    };

    let mut result = CheckResult::new();

    unsafe {
        // First, get the required buffer size
        let mut bytes_needed: u32 = 0;
        let success = EnumDeviceDrivers(std::ptr::null_mut(), 0, &mut bytes_needed);

        if success == 0 {
            let error = GetLastError();
            return Err(DriverError::WindowsApi {
                code: error,
                message: format!("EnumDeviceDrivers (size query) failed with error {}", error),
            });
        }

        if bytes_needed == 0 {
            return Err(DriverError::EnumerationFailed(
                "No drivers found or insufficient privileges".to_string(),
            ));
        }

        // Calculate number of drivers
        let ptr_size = mem::size_of::<usize>();
        let num_drivers = (bytes_needed as usize) / ptr_size;

        // Allocate buffer for driver addresses
        let mut driver_addresses: Vec<usize> = vec![0; num_drivers];

        // Enumerate drivers
        let success = EnumDeviceDrivers(
            driver_addresses.as_mut_ptr() as *mut _,
            bytes_needed,
            &mut bytes_needed,
        );

        if success == 0 {
            let error = GetLastError();
            return Err(DriverError::WindowsApi {
                code: error,
                message: format!("EnumDeviceDrivers failed with error {}", error),
            });
        }

        // Process each driver
        for &driver_address in &driver_addresses {
            if driver_address == 0 {
                continue;
            }

            // Get driver base name
            let mut base_name_buf = [0u16; 256];
            let base_name_len = GetDeviceDriverBaseNameW(
                driver_address as *const _,
                base_name_buf.as_mut_ptr(),
                base_name_buf.len() as u32,
            );

            if base_name_len == 0 {
                continue;
            }

            let base_name = String::from_utf16_lossy(&base_name_buf[..base_name_len as usize]);

            // Get driver file name
            let mut file_name_buf = [0u16; 256];
            let file_name_len = GetDeviceDriverFileNameW(
                driver_address as *const _,
                file_name_buf.as_mut_ptr(),
                file_name_buf.len() as u32,
            );

            if file_name_len == 0 {
                continue;
            }

            let file_name = String::from_utf16_lossy(&file_name_buf[..file_name_len as usize]);

            // Normalize the path
            let normalized_path = normalize_driver_path(&file_name);

            // Check this driver
            if let Some(detection) = check_driver(&base_name, &normalized_path) {
                result.detections.push(detection);
            }
        }
    }

    Ok(result)
}

/// Normalize driver path from kernel-mode format to user-mode format
#[cfg(windows)]
fn normalize_driver_path(path: &str) -> String {
    let path_lower = path.to_lowercase();

    // Handle \SystemRoot\ prefix
    if path_lower.starts_with("\\systemroot\\") {
        return path_lower.replace("\\systemroot\\", "c:\\windows\\");
    }

    // Handle \Windows\ prefix (add C: drive)
    if path_lower.starts_with("\\windows\\") {
        return path_lower.replace("\\windows\\", "c:\\windows\\");
    }

    // Handle \??\ prefix (DOS device path)
    if path_lower.starts_with("\\??\\") {
        return path_lower.replace("\\??\\", "");
    }

    // Return as-is if no special handling needed
    path.to_string()
}

#[cfg(windows)]
fn check_driver(base_name: &str, file_path: &str) -> Option<DriverDetection> {
    // Get file metadata
    let file_metadata = match file_info::get_file_info(std::path::Path::new(file_path)) {
        Ok(info) => Some(info.to_string()),
        Err(_) => None,
    };

    // Build searchable string
    let mut search_string = format!("{} - ", base_name);
    if let Some(ref metadata) = file_metadata {
        search_string.push_str(metadata);
    }

    // Check for matches
    let matches = find_matches(&search_string);

    if matches.is_empty() {
        None
    } else {
        Some(DriverDetection {
            base_name: base_name.to_string(),
            file_path: file_path.to_string(),
            file_metadata,
            matches,
        })
    }
}

/// Check loaded drivers (non-Windows stub)
#[cfg(not(windows))]
pub fn check_drivers() -> Result<CheckResult, DriverError> {
    Err(DriverError::EnumerationFailed(
        "Driver enumeration not supported on this platform".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_result_empty() {
        let result = CheckResult::new();
        assert!(!result.has_detections());
        assert_eq!(result.count(), 0);
        assert_eq!(result.to_string(), "[+] No suspicious drivers found");
    }

    #[test]
    fn test_check_result_with_detections() {
        let mut result = CheckResult::new();
        result.detections.push(DriverDetection {
            base_name: "csagent.sys".to_string(),
            file_path: "C:\\Windows\\System32\\drivers\\csagent.sys".to_string(),
            file_metadata: None,
            matches: vec!["csagent"],
        });

        assert!(result.has_detections());
        assert_eq!(result.count(), 1);

        let output = result.to_string();
        assert!(output.contains("Driver Summary"));
        assert!(output.contains("csagent.sys"));
    }

    #[test]
    #[cfg(windows)]
    fn test_normalize_driver_path_systemroot() {
        let path = "\\SystemRoot\\System32\\drivers\\test.sys";
        let normalized = normalize_driver_path(path);
        assert_eq!(normalized, "c:\\windows\\system32\\drivers\\test.sys");
    }

    #[test]
    #[cfg(windows)]
    fn test_normalize_driver_path_dos_device() {
        let path = "\\??\\C:\\Windows\\System32\\drivers\\test.sys";
        let normalized = normalize_driver_path(path);
        assert_eq!(normalized, "c:\\windows\\system32\\drivers\\test.sys");
    }

    #[test]
    #[cfg(not(windows))]
    fn test_check_drivers_not_supported() {
        let result = check_drivers();
        assert!(result.is_err());
    }
}
