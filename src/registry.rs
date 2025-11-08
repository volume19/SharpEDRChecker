//! Registry checking for EDR/AV detection
//!
//! Enumerates Windows registry keys to detect installed security products.

#[cfg(windows)]
use crate::edr_data::find_matches;
use crate::error::RegistryError;
use serde::Serialize;
use std::fmt;

/// Detection of an EDR/AV product in the Windows registry
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistryDetection {
    /// Registry key path
    pub key_path: String,
    /// Value name (if applicable)
    pub value_name: Option<String>,
    /// Value data
    pub value_data: Option<String>,
    /// Matched EDR signatures
    pub matches: Vec<&'static str>,
}

/// Result type for registry checking operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    /// List of registry detections found
    pub detections: Vec<RegistryDetection>,
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
            write!(f, "[+] No suspicious registry entries found")
        } else {
            writeln!(f, "[!] Registry Summary:")?;
            for detection in &self.detections {
                writeln!(
                    f,
                    "\t[-] {} : {}",
                    detection.key_path,
                    detection.matches.join(", ")
                )?;
            }
            Ok(())
        }
    }
}

/// Check Windows registry for EDR/AV products
///
/// Enumerates registry keys commonly used for software installation and services:
/// - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
/// - HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
/// - HKLM\SYSTEM\CurrentControlSet\Services
///
/// # Returns
///
/// * `Ok(CheckResult)` - Detection results (may be empty)
/// * `Err(RegistryError)` - If registry enumeration fails
///
/// # Example
///
/// ```no_run
/// use sharp_edr_checker::registry::check_registry;
///
/// match check_registry() {
///     Ok(result) => {
///         if result.has_detections() {
///             println!("{}", result);
///         }
///     }
///     Err(e) => eprintln!("Error checking registry: {}", e),
/// }
/// ```
#[cfg(windows)]
pub fn check_registry() -> Result<CheckResult, RegistryError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW,
        HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    };

    let mut result = CheckResult::new();

    // Registry paths to check
    let registry_paths = vec![
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SYSTEM\CurrentControlSet\Services",
    ];

    for path in registry_paths {
        if let Ok(detections) = enumerate_registry_key(path) {
            result.detections.extend(detections);
        }
    }

    Ok(result)
}

#[cfg(windows)]
fn enumerate_registry_key(path: &str) -> Result<Vec<RegistryDetection>, RegistryError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
        REG_SZ,
    };

    let mut detections = Vec::new();

    unsafe {
        // Convert path to wide string
        let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        // Open the registry key
        let mut hkey = 0isize;
        let result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide_path.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        );

        if result != ERROR_SUCCESS as i32 {
            return Ok(detections); // Key doesn't exist or no access - not an error
        }

        // Ensure key is closed on exit
        let _guard = RegKeyGuard(hkey);

        // Enumerate subkeys
        let mut index = 0;
        loop {
            let mut name_buffer = [0u16; 256];
            let mut name_len = name_buffer.len() as u32;

            let result = RegEnumKeyExW(
                hkey,
                index,
                name_buffer.as_mut_ptr(),
                &mut name_len,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );

            if result == ERROR_NO_MORE_ITEMS as i32 {
                break;
            }

            if result == ERROR_SUCCESS as i32 {
                let subkey_name = String::from_utf16_lossy(&name_buffer[..name_len as usize]);

                // Check the subkey name and its values
                let full_path = format!("{}\\{}", path, subkey_name);
                if let Some(detection) = check_registry_key(&full_path) {
                    detections.push(detection);
                }
            }

            index += 1;

            // Limit to prevent excessive enumeration
            if index > 1000 {
                break;
            }
        }
    }

    Ok(detections)
}

#[cfg(windows)]
fn check_registry_key(key_path: &str) -> Option<RegistryDetection> {
    use std::ptr;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    };

    unsafe {
        let wide_path: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();

        let mut hkey = 0isize;
        let result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide_path.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        );

        if result != ERROR_SUCCESS as i32 {
            return None;
        }

        let _guard = RegKeyGuard(hkey);

        // Common value names to check
        let value_names = vec!["DisplayName", "Publisher", "InstallLocation"];

        let mut search_text = key_path.to_string();

        for value_name in value_names {
            if let Some(value_data) = read_registry_string(hkey, value_name) {
                search_text.push_str(" - ");
                search_text.push_str(&value_data);
            }
        }

        // Check for EDR matches
        let matches = find_matches(&search_text);

        if matches.is_empty() {
            None
        } else {
            Some(RegistryDetection {
                key_path: key_path.to_string(),
                value_name: None,
                value_data: Some(search_text),
                matches,
            })
        }
    }
}

#[cfg(windows)]
fn read_registry_string(hkey: isize, value_name: &str) -> Option<String> {
    use std::ptr;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{RegQueryValueExW, REG_SZ};

    unsafe {
        let wide_name: Vec<u16> = value_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut buffer = vec![0u16; 1024];
        let mut buffer_size = (buffer.len() * 2) as u32;
        let mut value_type = 0u32;

        let result = RegQueryValueExW(
            hkey,
            wide_name.as_ptr(),
            ptr::null_mut(),
            &mut value_type,
            buffer.as_mut_ptr() as *mut u8,
            &mut buffer_size,
        );

        if result == ERROR_SUCCESS as i32 && value_type == REG_SZ {
            let len = (buffer_size as usize / 2).saturating_sub(1);
            String::from_utf16(&buffer[..len]).ok()
        } else {
            None
        }
    }
}

/// RAII guard for registry key handle
#[cfg(windows)]
struct RegKeyGuard(isize);

#[cfg(windows)]
impl Drop for RegKeyGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::Registry::RegCloseKey(self.0);
        }
    }
}

/// Check Windows registry (non-Windows stub)
#[cfg(not(windows))]
pub fn check_registry() -> Result<CheckResult, RegistryError> {
    Err(RegistryError::WindowsApi(
        "Registry checking not supported on this platform".to_string(),
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
        assert_eq!(
            result.to_string(),
            "[+] No suspicious registry entries found"
        );
    }

    #[test]
    fn test_check_result_with_detections() {
        let mut result = CheckResult::new();
        result.detections.push(RegistryDetection {
            key_path: r"SOFTWARE\CrowdStrike\FalconSensor".to_string(),
            value_name: Some("DisplayName".to_string()),
            value_data: Some("CrowdStrike Falcon Sensor".to_string()),
            matches: vec!["crowdstrike"],
        });

        assert!(result.has_detections());
        assert_eq!(result.count(), 1);

        let output = result.to_string();
        assert!(output.contains("Registry Summary"));
        assert!(output.contains("CrowdStrike"));
    }

    #[test]
    #[cfg(not(windows))]
    fn test_check_registry_not_supported() {
        let result = check_registry();
        assert!(result.is_err());
    }

    #[test]
    #[cfg(windows)]
    fn test_check_registry_runs() {
        // Just verify it runs without panicking
        // May or may not find detections depending on system
        let result = check_registry();
        assert!(result.is_ok());
    }
}
