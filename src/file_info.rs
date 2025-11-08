//! PE file version information extraction
//!
//! Extracts metadata from Windows executable files (.exe, .dll, .sys).

use crate::error::FileError;
use std::path::Path;

/// File version information extracted from PE metadata
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileVersionInfo {
    /// Product name from version resources
    pub product_name: Option<String>,
    /// Full path to the file
    pub filename: String,
    /// Original filename from version resources
    pub original_filename: Option<String>,
    /// Internal name from version resources
    pub internal_name: Option<String>,
    /// Company name from version resources
    pub company_name: Option<String>,
    /// File description from version resources
    pub file_description: Option<String>,
    /// Product version string
    pub product_version: Option<String>,
    /// Comments
    pub comments: Option<String>,
    /// Legal copyright
    pub legal_copyright: Option<String>,
    /// Legal trademarks
    pub legal_trademarks: Option<String>,
}

impl std::fmt::Display for FileVersionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\n\t\tProduct Name: {}", self.product_name.as_deref().unwrap_or(""))?;
        writeln!(f, "\t\tFilename: {}", self.filename)?;
        writeln!(f, "\t\tOriginal Filename: {}", self.original_filename.as_deref().unwrap_or(""))?;
        writeln!(f, "\t\tInternal Name: {}", self.internal_name.as_deref().unwrap_or(""))?;
        writeln!(f, "\t\tCompany Name: {}", self.company_name.as_deref().unwrap_or(""))?;
        writeln!(f, "\t\tFile Description: {}", self.file_description.as_deref().unwrap_or(""))?;
        writeln!(f, "\t\tProduct Version: {}", self.product_version.as_deref().unwrap_or(""))?;
        writeln!(f, "\t\tComments: {}", self.comments.as_deref().unwrap_or(""))?;
        writeln!(f, "\t\tLegal Copyright: {}", self.legal_copyright.as_deref().unwrap_or(""))?;
        write!(f, "\t\tLegal Trademarks: {}", self.legal_trademarks.as_deref().unwrap_or(""))
    }
}

/// Get file version information from a PE file
///
/// Extracts metadata from Windows executable files using the Windows version info API.
/// Handles WOW64 Sysnative redirection automatically.
///
/// # Arguments
///
/// * `path` - Path to the PE file (.exe, .dll, .sys, etc.)
///
/// # Returns
///
/// * `Ok(FileVersionInfo)` - Extracted version information
/// * `Err(FileError)` - If the file doesn't exist, can't be read, or has no version info
///
/// # Example
///
/// ```no_run
/// use std::path::Path;
/// use sharp_edr_checker::file_info::get_file_info;
///
/// let info = get_file_info(Path::new("C:\\Windows\\System32\\kernel32.dll"))?;
/// println!("Company: {}", info.company_name.unwrap_or_default());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(windows)]
pub fn get_file_info(path: &Path) -> Result<FileVersionInfo, FileError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    // Try the provided path first
    match get_file_info_inner(path) {
        Ok(info) => Ok(info),
        Err(FileError::NotFound { .. }) => {
            // Handle WOW64 Sysnative redirection
            if let Some(path_str) = path.to_str() {
                let lower = path_str.to_lowercase();
                if lower.starts_with("c:\\windows\\system32\\") {
                    let sysnative_path = path_str.replace("c:\\windows\\system32\\", "c:\\Windows\\Sysnative\\")
                        .replace("C:\\Windows\\System32\\", "C:\\Windows\\Sysnative\\");
                    return get_file_info_inner(Path::new(&sysnative_path));
                }
            }
            Err(FileError::NotFound {
                path: path.display().to_string(),
            })
        }
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn get_file_info_inner(path: &Path) -> Result<FileVersionInfo, FileError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_RESOURCE_DATA_NOT_FOUND, ERROR_RESOURCE_TYPE_NOT_FOUND};
    use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};

    // Convert path to wide string
    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // Get the size of version info
        let mut handle: u32 = 0;
        let size = GetFileVersionInfoSizeW(wide_path.as_ptr(), &mut handle);

        if size == 0 {
            let error = windows_sys::Win32::Foundation::GetLastError();
            return match error {
                ERROR_FILE_NOT_FOUND => Err(FileError::NotFound {
                    path: path.display().to_string(),
                }),
                ERROR_RESOURCE_DATA_NOT_FOUND | ERROR_RESOURCE_TYPE_NOT_FOUND => {
                    Err(FileError::ParseError(
                        "File has no version information".to_string(),
                    ))
                }
                _ => Err(FileError::WindowsApi(format!(
                    "GetFileVersionInfoSizeW failed with error {}",
                    error
                ))),
            };
        }

        // Allocate buffer for version info
        let mut buffer = vec![0u8; size as usize];

        // Get version info
        let result = GetFileVersionInfoW(
            wide_path.as_ptr(),
            handle,
            size,
            buffer.as_mut_ptr() as *mut _,
        );

        if result == 0 {
            let error = windows_sys::Win32::Foundation::GetLastError();
            return Err(FileError::WindowsApi(format!(
                "GetFileVersionInfoW failed with error {}",
                error
            )));
        }

        // Query string file info
        let mut info = FileVersionInfo {
            filename: path.display().to_string(),
            ..Default::default()
        };

        // Try to extract strings from version info
        // We need to query \\VarFileInfo\\Translation first to get language/codepage
        let translation_key: Vec<u16> = OsStr::new("\\VarFileInfo\\Translation")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut trans_ptr: *mut u8 = ptr::null_mut();
        let mut trans_len: u32 = 0;

        let trans_result = VerQueryValueW(
            buffer.as_ptr() as *const _,
            translation_key.as_ptr(),
            &mut trans_ptr as *mut _ as *mut *mut _,
            &mut trans_len,
        );

        let lang_cp = if trans_result != 0 && trans_len >= 4 {
            let trans_data = std::slice::from_raw_parts(trans_ptr as *const u16, 2);
            format!("{:04x}{:04x}", trans_data[0], trans_data[1])
        } else {
            // Default to US English
            "040904b0".to_string()
        };

        // Helper closure to query a string value
        let query_string = |key: &str| -> Option<String> {
            let query_key = format!("\\StringFileInfo\\{}\\{}", lang_cp, key);
            let wide_key: Vec<u16> = OsStr::new(&query_key)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut value_ptr: *mut u16 = ptr::null_mut();
            let mut value_len: u32 = 0;

            let result = VerQueryValueW(
                buffer.as_ptr() as *const _,
                wide_key.as_ptr(),
                &mut value_ptr as *mut _ as *mut *mut _,
                &mut value_len,
            );

            if result != 0 && !value_ptr.is_null() && value_len > 0 {
                // Convert from wide string to Rust String
                let slice = std::slice::from_raw_parts(value_ptr, value_len as usize);
                // Find null terminator
                let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
                String::from_utf16(&slice[..end]).ok()
            } else {
                None
            }
        };

        info.product_name = query_string("ProductName");
        info.original_filename = query_string("OriginalFilename");
        info.internal_name = query_string("InternalName");
        info.company_name = query_string("CompanyName");
        info.file_description = query_string("FileDescription");
        info.product_version = query_string("ProductVersion");
        info.comments = query_string("Comments");
        info.legal_copyright = query_string("LegalCopyright");
        info.legal_trademarks = query_string("LegalTrademarks");

        Ok(info)
    }
}

/// Get file version information (non-Windows stub)
#[cfg(not(windows))]
pub fn get_file_info(_path: &Path) -> Result<FileVersionInfo, FileError> {
    Err(FileError::WindowsApi(
        "File version info extraction not supported on this platform".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_version_info_default() {
        let info = FileVersionInfo::default();
        assert_eq!(info.product_name, None);
        assert_eq!(info.company_name, None);
    }

    #[test]
    #[cfg(windows)]
    fn test_get_file_info_kernel32() {
        // kernel32.dll should exist on all Windows systems
        let path = Path::new("C:\\Windows\\System32\\kernel32.dll");

        match get_file_info(path) {
            Ok(info) => {
                // Basic sanity checks
                assert!(info.filename.contains("kernel32"));
                // Microsoft file should have company name
                if let Some(company) = info.company_name {
                    assert!(company.to_lowercase().contains("microsoft"));
                }
            }
            Err(e) => {
                // On some systems we might not have permission
                println!("Warning: Could not read kernel32.dll info: {}", e);
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_get_file_info_nonexistent() {
        let path = Path::new("C:\\this_file_does_not_exist_12345.dll");
        let result = get_file_info(path);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FileError::NotFound { .. }));
    }

    #[test]
    #[cfg(not(windows))]
    fn test_get_file_info_not_supported() {
        let path = Path::new("/some/file.dll");
        let result = get_file_info(path);
        assert!(result.is_err());
    }
}
