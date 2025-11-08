//! Windows service enumeration and EDR detection
//!
//! Enumerates Windows services via WMI and checks for EDR/AV products.

#[cfg(windows)]
use crate::edr_data::find_matches;
use crate::error::ServiceError;
#[cfg(windows)]
use crate::file_info;
use serde::Serialize;
use std::fmt;

/// Detection of an EDR/AV product in a Windows service
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceDetection {
    /// Service name
    pub name: String,
    /// Service display name
    pub display_name: String,
    /// Service description
    pub description: Option<String>,
    /// Service binary path
    pub path_name: Option<String>,
    /// Service state (Running, Stopped, etc.)
    pub state: Option<String>,
    /// Process ID (if running)
    pub process_id: Option<u32>,
    /// File metadata from the service binary
    pub file_metadata: Option<String>,
    /// Matched EDR signatures
    pub matches: Vec<&'static str>,
}

/// Result of service checking operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    /// List of service detections found
    pub detections: Vec<ServiceDetection>,
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
            write!(f, "[+] No suspicious services found")
        } else {
            writeln!(f, "[!] Service Summary:")?;
            for detection in &self.detections {
                writeln!(
                    f,
                    "\t[-] {} : {}",
                    detection.name,
                    detection.matches.join(", ")
                )?;
            }
            Ok(())
        }
    }
}

/// Check Windows services for EDR/AV products
///
/// Enumerates all Windows services using WMI and checks their metadata
/// against EDR signatures.
///
/// # Returns
///
/// * `Ok(CheckResult)` - Detection results (may be empty)
/// * `Err(ServiceError)` - If WMI query or enumeration fails
///
/// # Example
///
/// ```no_run
/// use sharp_edr_checker::service::check_services;
///
/// match check_services() {
///     Ok(result) => {
///         if result.has_detections() {
///             println!("{}", result);
///         }
///     }
///     Err(e) => eprintln!("Error checking services: {}", e),
/// }
/// ```
#[cfg(windows)]
pub fn check_services() -> Result<CheckResult, ServiceError> {
    use wmi::{COMLibrary, Variant, WMIConnection};

    let com_con = COMLibrary::new().map_err(|e| ServiceError::WmiError(format!("{}", e)))?;
    let wmi_con = WMIConnection::new(com_con.into())
        .map_err(|e| ServiceError::WmiError(format!("{}", e)))?;

    // Query all services
    let results: Vec<std::collections::HashMap<String, Variant>> = wmi_con
        .raw_query("SELECT * FROM Win32_Service")
        .map_err(|e| ServiceError::WmiError(format!("WMI query failed: {}", e)))?;

    let mut check_result = CheckResult::new();

    for service in results {
        if let Some(detection) = check_service(&service) {
            check_result.detections.push(detection);
        }
    }

    Ok(check_result)
}

#[cfg(windows)]
fn check_service(
    service: &std::collections::HashMap<String, wmi::Variant>,
) -> Option<ServiceDetection> {
    use wmi::Variant;

    // Extract service fields
    let name = match service.get("Name") {
        Some(Variant::String(s)) => s.clone(),
        _ => return None,
    };

    let display_name = match service.get("DisplayName") {
        Some(Variant::String(s)) => s.clone(),
        _ => String::new(),
    };

    let description = match service.get("Description") {
        Some(Variant::String(s)) => Some(s.clone()),
        _ => None,
    };

    let caption = match service.get("Caption") {
        Some(Variant::String(s)) => Some(s.clone()),
        _ => None,
    };

    let path_name = match service.get("PathName") {
        Some(Variant::String(s)) => Some(s.clone()),
        _ => None,
    };

    let state = match service.get("State") {
        Some(Variant::String(s)) => Some(s.clone()),
        _ => None,
    };

    let process_id = match service.get("ProcessId") {
        Some(Variant::UI4(id)) => Some(*id),
        _ => None,
    };

    // Get file metadata if path is available
    let file_metadata = if let Some(ref path) = path_name {
        extract_file_metadata_from_path(path)
    } else {
        None
    };

    // Build searchable string from all attributes
    let mut search_string = format!("{} - {} - ", name, display_name);
    if let Some(ref desc) = description {
        search_string.push_str(desc);
        search_string.push_str(" - ");
    }
    if let Some(ref cap) = caption {
        search_string.push_str(cap);
        search_string.push_str(" - ");
    }
    if let Some(ref path) = path_name {
        search_string.push_str(path);
        search_string.push_str(" - ");
    }
    if let Some(ref metadata) = file_metadata {
        search_string.push_str(metadata);
    }

    // Check for matches
    let matches = find_matches(&search_string);

    if matches.is_empty() {
        None
    } else {
        Some(ServiceDetection {
            name,
            display_name,
            description,
            path_name,
            state,
            process_id,
            file_metadata,
            matches,
        })
    }
}

#[cfg(windows)]
fn extract_file_metadata_from_path(path_name: &str) -> Option<String> {
    // Extract .exe path from service PathName (may contain quotes and arguments)
    let exe_index = path_name.to_lowercase().find(".exe")?;
    let file_path = &path_name[..exe_index + 4]; // Include ".exe"
    let file_path = file_path.trim_matches('"');

    // Get file version info
    match file_info::get_file_info(std::path::Path::new(file_path)) {
        Ok(info) => Some(info.to_string()),
        Err(_) => None,
    }
}

/// Check Windows services (non-Windows stub)
#[cfg(not(windows))]
pub fn check_services() -> Result<CheckResult, ServiceError> {
    Err(ServiceError::WmiError(
        "Service enumeration not supported on this platform".to_string(),
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
        assert_eq!(result.to_string(), "[+] No suspicious services found");
    }

    #[test]
    fn test_check_result_with_detections() {
        let mut result = CheckResult::new();
        result.detections.push(ServiceDetection {
            name: "CrowdStrike Falcon".to_string(),
            display_name: "CrowdStrike Falcon Sensor Service".to_string(),
            description: Some("Endpoint protection".to_string()),
            path_name: Some("C:\\Program Files\\CrowdStrike\\CSFalconService.exe".to_string()),
            state: Some("Running".to_string()),
            process_id: Some(1234),
            file_metadata: None,
            matches: vec!["crowdstrike", "csfalcon"],
        });

        assert!(result.has_detections());
        assert_eq!(result.count(), 1);

        let output = result.to_string();
        assert!(output.contains("Service Summary"));
        assert!(output.contains("CrowdStrike Falcon"));
    }

    #[test]
    #[cfg(not(windows))]
    fn test_check_services_not_supported() {
        let result = check_services();
        assert!(result.is_err());
    }
}
