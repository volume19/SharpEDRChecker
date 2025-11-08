//! Integration tests for SharpEDRChecker
//!
//! These tests verify end-to-end functionality of the EDR detection system.

use sharp_edr_checker::{directory, driver, edr_data, privilege, process, service};

#[test]
fn test_edr_signature_matching() {
    // Test that EDR signatures can be found in sample text
    let matches = edr_data::find_matches("CrowdStrike Falcon Sensor Service");
    assert!(!matches.is_empty());
    assert!(matches.contains(&"crowdstrike"));
}

#[test]
fn test_privilege_check_non_panic() {
    // Verify privilege check doesn't panic (may return error on non-Windows)
    let result = privilege::check_is_admin();

    #[cfg(windows)]
    {
        // On Windows, should return Ok with boolean
        assert!(result.is_ok());
    }

    #[cfg(not(windows))]
    {
        // On non-Windows, should return error
        assert!(result.is_err());
    }
}

#[test]
fn test_directory_check_runs() {
    // Verify directory check completes without panic
    let result = directory::check_directories();
    assert!(result.is_ok());

    let check_result = result.unwrap();
    // Count should be >= 0 (empty is valid)
    assert!(check_result.count() >= 0);
}

#[test]
#[cfg(windows)]
fn test_service_check_windows() {
    // On Windows, service check should succeed
    let result = service::check_services();
    assert!(result.is_ok(), "Service check should succeed on Windows");
}

#[test]
#[cfg(not(windows))]
fn test_service_check_non_windows() {
    // On non-Windows, should return not supported error
    let result = service::check_services();
    assert!(result.is_err(), "Service check should fail on non-Windows");
}

#[test]
#[cfg(windows)]
fn test_process_check_windows() {
    // On Windows, process check should succeed
    let result = process::check_processes();
    assert!(result.is_ok(), "Process check should succeed on Windows");
}

#[test]
#[cfg(not(windows))]
fn test_process_check_non_windows() {
    // On non-Windows, should return not supported error
    let result = process::check_processes();
    assert!(result.is_err(), "Process check should fail on non-Windows");
}

#[test]
#[cfg(windows)]
fn test_module_check_windows() {
    // On Windows, module check should succeed
    let result = process::check_current_process_modules();
    assert!(result.is_ok(), "Module check should succeed on Windows");
}

#[test]
#[cfg(windows)]
fn test_driver_check_windows() {
    // On Windows, driver check should succeed (may require admin for full results)
    let result = driver::check_drivers();

    // Should return Ok even without admin (may have limited results)
    assert!(result.is_ok(), "Driver check should succeed on Windows");
}

#[test]
#[cfg(not(windows))]
fn test_driver_check_non_windows() {
    // On non-Windows, should return not supported error
    let result = driver::check_drivers();
    assert!(result.is_err(), "Driver check should fail on non-Windows");
}

#[test]
fn test_all_checkers_non_panic() {
    // Verify all checkers can be called without panicking
    // This is important for robust error handling

    let _ = privilege::check_is_admin();
    let _ = directory::check_directories();
    let _ = service::check_services();
    let _ = process::check_processes();
    let _ = process::check_current_process_modules();
    let _ = driver::check_drivers();

    // If we reach here, no panics occurred
    assert!(true);
}

#[test]
fn test_check_result_display() {
    // Verify CheckResult Display implementations work
    let dir_result = directory::CheckResult::new();
    let dir_output = format!("{}", dir_result);
    assert!(dir_output.contains("No suspicious directories"));

    let svc_result = service::CheckResult::new();
    let svc_output = format!("{}", svc_result);
    assert!(svc_output.contains("No suspicious services"));
}
