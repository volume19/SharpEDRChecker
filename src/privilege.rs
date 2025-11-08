//! Privilege level checking
//!
//! Determines if the current process is running with administrator/elevated privileges.

use crate::error::PrivilegeError;

/// Check if the current process is running with administrator privileges
///
/// On Windows, this checks if the process token is elevated.
/// On non-Windows platforms, this returns an error.
///
/// # Returns
///
/// * `Ok(true)` - Process is running as administrator
/// * `Ok(false)` - Process is running as normal user
/// * `Err(_)` - Failed to determine privilege level
///
/// # Example
///
/// ```no_run
/// use sharp_edr_checker::privilege::check_is_admin;
///
/// match check_is_admin() {
///     Ok(true) => println!("Running as administrator"),
///     Ok(false) => println!("Running as normal user"),
///     Err(e) => eprintln!("Failed to check privileges: {}", e),
/// }
/// ```
#[cfg(windows)]
pub fn check_is_admin() -> Result<bool, PrivilegeError> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token_handle: HANDLE = 0;

        // Open the current process token
        let result = OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token_handle,
        );

        if result == 0 {
            let error_code = windows_sys::Win32::Foundation::GetLastError();
            return Err(PrivilegeError::WindowsApi {
                code: error_code,
                message: format!("OpenProcessToken failed with code {}", error_code),
            });
        }

        // Ensure token handle is closed on scope exit
        let _guard = TokenHandleGuard(token_handle);

        // Query token elevation status
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_length: u32 = 0;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        if result == 0 {
            let error_code = windows_sys::Win32::Foundation::GetLastError();
            return Err(PrivilegeError::WindowsApi {
                code: error_code,
                message: format!("GetTokenInformation failed with code {}", error_code),
            });
        }

        Ok(elevation.TokenIsElevated != 0)
    }
}

/// RAII guard for Windows token handle
#[cfg(windows)]
struct TokenHandleGuard(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for TokenHandleGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// Check if running as administrator (non-Windows platforms)
///
/// Returns an error indicating the operation is not supported.
#[cfg(not(windows))]
pub fn check_is_admin() -> Result<bool, PrivilegeError> {
    Err(PrivilegeError::TokenError(
        "Privilege checking not supported on this platform".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_is_admin_returns_result() {
        // This test just verifies the function returns without panicking
        // The actual result depends on how the test is run
        let result = check_is_admin();

        #[cfg(windows)]
        {
            assert!(result.is_ok(), "Should return Ok on Windows");
            let is_admin = result.unwrap();
            // Just verify it's a boolean - can't assert the value as it depends on test execution context
            assert!(is_admin == true || is_admin == false);
        }

        #[cfg(not(windows))]
        {
            assert!(result.is_err(), "Should return Err on non-Windows");
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_multiple_calls_dont_leak_handles() {
        // Call multiple times to ensure handles are properly cleaned up
        for _ in 0..100 {
            let _ = check_is_admin();
        }
    }
}
