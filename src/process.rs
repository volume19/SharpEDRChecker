//! Process enumeration and EDR detection
//!
//! Enumerates running processes via WMI and checks loaded modules in current process.

#[cfg(windows)]
use crate::edr_data::find_matches;
use crate::error::ProcessError;
#[cfg(windows)]
use crate::file_info;
use std::fmt;

/// Detection of an EDR/AV product in a running process
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessDetection {
    /// Process name
    pub name: String,
    /// Executable path
    pub executable_path: Option<String>,
    /// Process description
    pub description: Option<String>,
    /// Command line
    pub command_line: Option<String>,
    /// Process ID
    pub process_id: Option<u32>,
    /// Parent process ID
    pub parent_process_id: Option<u32>,
    /// File metadata from the executable
    pub file_metadata: Option<String>,
    /// Matched EDR signatures
    pub matches: Vec<&'static str>,
}

/// Detection of an EDR/AV product in a loaded module
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDetection {
    /// Module file path
    pub file_path: String,
    /// File metadata
    pub file_metadata: Option<String>,
    /// Matched EDR signatures
    pub matches: Vec<&'static str>,
}

/// Result of process checking operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    /// List of process detections found
    pub process_detections: Vec<ProcessDetection>,
    /// List of module detections found
    pub module_detections: Vec<ModuleDetection>,
}

impl CheckResult {
    /// Create a new empty check result
    pub fn new() -> Self {
        Self {
            process_detections: Vec::new(),
            module_detections: Vec::new(),
        }
    }

    /// Returns true if any detections were found
    pub fn has_detections(&self) -> bool {
        !self.process_detections.is_empty() || !self.module_detections.is_empty()
    }

    /// Returns the total number of detections
    pub fn count(&self) -> usize {
        self.process_detections.len() + self.module_detections.len()
    }
}

impl Default for CheckResult {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.process_detections.is_empty() {
            writeln!(f, "[+] No suspicious processes found")?;
        } else {
            writeln!(f, "[!] Process Summary:")?;
            for detection in &self.process_detections {
                writeln!(
                    f,
                    "\t[-] {} : {}",
                    detection.name,
                    detection.matches.join(", ")
                )?;
            }
        }

        if self.module_detections.is_empty() {
            write!(f, "[+] No suspicious modules found in your process")?;
        } else {
            writeln!(f, "[!] Modload Summary:")?;
            for detection in &self.module_detections {
                writeln!(
                    f,
                    "\t[-] {} : {}",
                    detection.file_path,
                    detection.matches.join(", ")
                )?;
            }
        }

        Ok(())
    }
}

/// Check running processes for EDR/AV products
///
/// Enumerates all running processes using WMI and checks their metadata
/// against EDR signatures.
///
/// # Returns
///
/// * `Ok(CheckResult)` - Detection results (may be empty)
/// * `Err(ProcessError)` - If WMI query or enumeration fails
#[cfg(windows)]
pub fn check_processes() -> Result<CheckResult, ProcessError> {
    use wmi::{COMLibrary, Variant, WMIConnection};

    let com_con = COMLibrary::new().map_err(|e| ProcessError::WmiError(format!("{}", e)))?;
    let wmi_con = WMIConnection::new(com_con.into())
        .map_err(|e| ProcessError::WmiError(format!("{}", e)))?;

    // Query all processes
    let results: Vec<std::collections::HashMap<String, Variant>> = wmi_con
        .raw_query("SELECT * FROM Win32_Process")
        .map_err(|e| ProcessError::WmiError(format!("WMI query failed: {}", e)))?;

    let mut check_result = CheckResult::new();

    for process in results {
        if let Some(detection) = check_process(&process) {
            check_result.process_detections.push(detection);
        }
    }

    Ok(check_result)
}

#[cfg(windows)]
fn check_process(
    process: &std::collections::HashMap<String, wmi::Variant>,
) -> Option<ProcessDetection> {
    use wmi::Variant;

    // Extract process fields
    let name = match process.get("Name") {
        Some(Variant::String(s)) => s.clone(),
        _ => return None,
    };

    let executable_path = match process.get("ExecutablePath") {
        Some(Variant::String(s)) => Some(s.clone()),
        _ => None,
    };

    let description = match process.get("Description") {
        Some(Variant::String(s)) => Some(s.clone()),
        _ => None,
    };

    let caption = match process.get("Caption") {
        Some(Variant::String(s)) => Some(s.clone()),
        _ => None,
    };

    let command_line = match process.get("CommandLine") {
        Some(Variant::String(s)) => Some(s.clone()),
        _ => None,
    };

    let process_id = match process.get("ProcessId") {
        Some(Variant::UI4(id)) => Some(*id),
        _ => None,
    };

    let parent_process_id = match process.get("ParentProcessId") {
        Some(Variant::UI4(id)) => Some(*id),
        _ => None,
    };

    // Get file metadata if path is available
    let file_metadata = if let Some(ref path) = executable_path {
        match file_info::get_file_info(std::path::Path::new(path)) {
            Ok(info) => Some(info.to_string()),
            Err(_) => None,
        }
    } else {
        None
    };

    // Build searchable string from all attributes
    let mut search_string = format!("{} - ", name);
    if let Some(ref path) = executable_path {
        search_string.push_str(path);
        search_string.push_str(" - ");
    }
    if let Some(ref desc) = description {
        search_string.push_str(desc);
        search_string.push_str(" - ");
    }
    if let Some(ref cap) = caption {
        search_string.push_str(cap);
        search_string.push_str(" - ");
    }
    if let Some(ref cmd) = command_line {
        search_string.push_str(cmd);
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
        Some(ProcessDetection {
            name,
            executable_path,
            description,
            command_line,
            process_id,
            parent_process_id,
            file_metadata,
            matches,
        })
    }
}

/// Check running processes (non-Windows stub)
#[cfg(not(windows))]
pub fn check_processes() -> Result<CheckResult, ProcessError> {
    Err(ProcessError::WmiError(
        "Process enumeration not supported on this platform".to_string(),
    ))
}

/// Check modules loaded in the current process for EDR/AV products
///
/// Enumerates DLLs loaded in the current process and checks for EDR hooks or modules.
///
/// # Returns
///
/// * `Ok(CheckResult)` - Detection results (may be empty)
/// * `Err(ProcessError)` - If module enumeration fails
#[cfg(windows)]
pub fn check_current_process_modules() -> Result<CheckResult, ProcessError> {
    use std::mem;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, MAX_PATH};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;

    let mut result = CheckResult::new();

    unsafe {
        let process_id = GetCurrentProcessId();

        // Create snapshot of modules in current process
        let snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            process_id,
        );

        if snapshot == -1isize as HANDLE {
            let error = GetLastError();
            return Err(ProcessError::ModuleEnumeration(format!(
                "CreateToolhelp32Snapshot failed with error {}",
                error
            )));
        }

        // Ensure snapshot handle is closed
        let _guard = SnapshotHandleGuard(snapshot);

        let mut module_entry: MODULEENTRY32W = mem::zeroed();
        module_entry.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;

        // Get first module
        if Module32FirstW(snapshot, &mut module_entry) == 0 {
            let error = GetLastError();
            return Err(ProcessError::ModuleEnumeration(format!(
                "Module32FirstW failed with error {}",
                error
            )));
        }

        // Iterate through modules
        loop {
            // Convert module path from wide string
            let path_len = module_entry
                .szExePath
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(MAX_PATH as usize);
            let module_path = String::from_utf16_lossy(&module_entry.szExePath[..path_len]);

            if let Some(detection) = check_module(&module_path) {
                result.module_detections.push(detection);
            }

            // Get next module
            if Module32NextW(snapshot, &mut module_entry) == 0 {
                break;
            }
        }
    }

    Ok(result)
}

#[cfg(windows)]
fn check_module(module_path: &str) -> Option<ModuleDetection> {
    // Get file metadata
    let file_metadata = match file_info::get_file_info(std::path::Path::new(module_path)) {
        Ok(info) => Some(info.to_string()),
        Err(_) => None,
    };

    // Build searchable string
    let mut search_string = module_path.to_string();
    if let Some(ref metadata) = file_metadata {
        search_string.push_str(" - ");
        search_string.push_str(metadata);
    }

    // Check for matches
    let matches = find_matches(&search_string);

    if matches.is_empty() {
        None
    } else {
        Some(ModuleDetection {
            file_path: module_path.to_string(),
            file_metadata,
            matches,
        })
    }
}

/// RAII guard for snapshot handle
#[cfg(windows)]
struct SnapshotHandleGuard(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for SnapshotHandleGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// Check current process modules (non-Windows stub)
#[cfg(not(windows))]
pub fn check_current_process_modules() -> Result<CheckResult, ProcessError> {
    Err(ProcessError::ModuleEnumeration(
        "Module enumeration not supported on this platform".to_string(),
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
    }

    #[test]
    fn test_check_result_with_process_detections() {
        let mut result = CheckResult::new();
        result.process_detections.push(ProcessDetection {
            name: "csagent.exe".to_string(),
            executable_path: Some("C:\\Program Files\\CrowdStrike\\csagent.exe".to_string()),
            description: Some("CrowdStrike Agent".to_string()),
            command_line: Some("csagent.exe".to_string()),
            process_id: Some(1234),
            parent_process_id: Some(100),
            file_metadata: None,
            matches: vec!["csagent", "crowdstrike"],
        });

        assert!(result.has_detections());
        assert_eq!(result.count(), 1);

        let output = result.to_string();
        assert!(output.contains("Process Summary"));
        assert!(output.contains("csagent.exe"));
    }

    #[test]
    fn test_check_result_with_module_detections() {
        let mut result = CheckResult::new();
        result.module_detections.push(ModuleDetection {
            file_path: "C:\\Windows\\System32\\amsi.dll".to_string(),
            file_metadata: None,
            matches: vec!["amsi.dll"],
        });

        assert!(result.has_detections());
        assert_eq!(result.count(), 1);

        let output = result.to_string();
        assert!(output.contains("Modload Summary"));
        assert!(output.contains("amsi.dll"));
    }

    #[test]
    #[cfg(not(windows))]
    fn test_check_processes_not_supported() {
        let result = check_processes();
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(windows))]
    fn test_check_current_process_modules_not_supported() {
        let result = check_current_process_modules();
        assert!(result.is_err());
    }
}
