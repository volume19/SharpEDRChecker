//! EDR/AV/Logging product signatures
//!
//! Static list of product names and identifiers used for detection.
//! All signatures are lowercase for case-insensitive matching.

/// Static array of EDR/AV/logging product signatures for detection
///
/// This list contains common strings found in process names, service names,
/// directory names, driver names, and file metadata for security products.
///
/// # Usage
///
/// ```
/// use sharp_edr_checker::edr_data::EDR_SIGNATURES;
///
/// let search_text = "CrowdStrike Falcon Sensor";
/// let matches: Vec<&&str> = EDR_SIGNATURES
///     .iter()
///     .filter(|sig| search_text.to_lowercase().contains(*sig))
///     .collect();
/// ```
pub static EDR_SIGNATURES: &[&str] = &[
    "activeconsole",
    "ada-precheck",
    "ahnlab",
    "amsi.dll",
    "anti malware",
    "anti-malware",
    "antimalware",
    "anti virus",
    "anti-virus",
    "antivirus",
    "appsense",
    "arctic wolf",
    "attivo networks",
    "attivonetworks",
    "authtap",
    "avast",
    "avira",
    "avecto",
    "bitdefender",
    "blackberry",
    "canary",
    "carbonblack",
    "carbon black",
    "cb.exe",
    "check point",
    "cisco",
    "ciscoamp",
    "cisco amp",
    "countercept",
    "countertack",
    "cramtray",
    "crssvc",
    "crowdstrike",
    "csagent",
    "csfalcon",
    "csshell",
    "cybereason",
    "cyclorama",
    "cylance",
    "cynet",
    "cyoptics",
    "cyupdate",
    "cyvera",
    "cyserver",
    "cytray",
    "darktrace",
    "deep instinct",
    "defendpoint",
    "defender",
    "eectrl",
    "elastic",
    "endgame",
    "f-secure",
    "forcepoint",
    "fortinet",
    "fireeye",
    "groundling",
    "grrservic",
    "harfanglab",
    "huntress",
    "inspector",
    "ivanti",
    "jamf",
    "juniper networks",
    "kandji",
    "kaspersky",
    "lacuna",
    "logrhythm",
    "malware",
    "malwarebytes",
    "mandiant",
    "mcafee",
    "morphisec",
    "msascuil",
    "msmpeng",
    "nissrv",
    "norton",
    "omni",
    "omniagent",
    "osquery",
    "palo alto networks",
    "pgeposervice",
    "pgsystemtray",
    "privilegeguard",
    "procwall",
    "protectorservic",
    "qianxin",
    "qradar",
    "qualys",
    "rapid7",
    "redcloak",
    "red canary",
    "sanernow",
    "sangfor",
    "secureworks",
    "securityhealthservice",
    "semlaunchsv",
    "sentinel",
    "sentinelone",
    "sepliveupdat",
    "sisidsservice",
    "sisipsservice",
    "sisipsutil",
    "smc.exe",
    "smcgui",
    "snac64",
    "somma",
    "sophos",
    "splunk",
    "srtsp",
    "symantec",
    "symcorpu",
    "symefasi",
    "sysinternal",
    "sysmon",
    "tanium",
    "tda.exe",
    "tdawork",
    "tehtris",
    "threat",
    "trellix",
    "tpython",
    "trend micro",
    "uptycs",
    "vectra",
    "watchguard",
    "wincollect",
    "windowssensor",
    "wireshark",
    "withsecure",
    "xagt.exe",
    "xagtnotif.exe",
];

/// Helper function to find matching EDR signatures in a text string
///
/// # Arguments
///
/// * `text` - The text to search (process name, service name, etc.)
///
/// # Returns
///
/// Vector of matching signature strings
///
/// # Example
///
/// ```
/// use sharp_edr_checker::edr_data::find_matches;
///
/// let matches = find_matches("CrowdStrike Falcon Sensor Service");
/// assert!(matches.contains(&"crowdstrike"));
/// ```
pub fn find_matches(text: &str) -> Vec<&'static str> {
    let text_lower = text.to_lowercase();
    EDR_SIGNATURES
        .iter()
        .filter(|sig| text_lower.contains(*sig))
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_count() {
        // Original C# has 132 entries (counted from EDRData.cs lines 6-139)
        assert_eq!(EDR_SIGNATURES.len(), 132);
    }

    #[test]
    fn test_find_matches_crowdstrike() {
        let matches = find_matches("CrowdStrike Falcon Sensor");
        assert_eq!(matches.len(), 1);
        assert!(matches.contains(&"crowdstrike"));
    }

    #[test]
    fn test_find_matches_case_insensitive() {
        let matches = find_matches("CROWDSTRIKE");
        assert!(matches.contains(&"crowdstrike"));
    }

    #[test]
    fn test_find_matches_multiple() {
        let matches = find_matches("Windows Defender Anti-Virus Service");
        assert!(matches.len() >= 2); // "defender", "anti-virus", "antivirus", etc.
        assert!(matches.contains(&"defender"));
    }

    #[test]
    fn test_find_matches_none() {
        let matches = find_matches("notepad.exe");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_find_matches_partial() {
        let matches = find_matches("csfalconservice.exe");
        assert!(matches.contains(&"csfalcon"));
        assert!(matches.contains(&"crowdstrike") == false); // Should not match crowdstrike
    }

    #[test]
    fn test_all_signatures_lowercase() {
        for sig in EDR_SIGNATURES.iter() {
            assert_eq!(
                *sig,
                sig.to_lowercase(),
                "Signature '{}' is not lowercase",
                sig
            );
        }
    }
}
