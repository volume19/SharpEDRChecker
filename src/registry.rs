//! Registry checking (not yet implemented)
//!
//! Placeholder module for future registry-based EDR detection.

use crate::error::RegistryError;

/// Result type for registry checking operations
///
/// Currently not used, but reserved for future implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    // Future: detections will go here
    _placeholder: (),
}

impl CheckResult {
    /// Create a new empty check result
    pub fn new() -> Self {
        Self { _placeholder: () }
    }
}

impl Default for CheckResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Check Windows registry for EDR/AV products
///
/// **Not yet implemented.** This function currently always returns
/// a `NotImplemented` error.
///
/// Future implementation will scan registry keys such as:
/// - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
/// - HKLM\SYSTEM\CurrentControlSet\Services
/// - Detection of service and application registry entries
///
/// # Returns
///
/// * `Err(RegistryError::NotImplemented)` - Always (not yet implemented)
///
/// # Example
///
/// ```
/// use sharp_edr_checker::registry::check_registry;
///
/// match check_registry() {
///     Ok(_result) => unreachable!("Not yet implemented"),
///     Err(e) => println!("Registry checking not available: {}", e),
/// }
/// ```
pub fn check_registry() -> Result<CheckResult, RegistryError> {
    Err(RegistryError::NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_registry_not_implemented() {
        let result = check_registry();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RegistryError::NotImplemented));
    }

    #[test]
    fn test_check_result_creation() {
        let result = CheckResult::new();
        let result_default = CheckResult::default();
        assert_eq!(result, result_default);
    }
}
