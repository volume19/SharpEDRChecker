//! SharpEDRChecker binary entry point

use sharp_edr_checker::{directory, driver, privilege, service};
use sharp_edr_checker::process as edr_process;

fn main() {
    if let Err(e) = run() {
        eprintln!("[-] Error running SharpEDRChecker: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Check privilege level
    let is_admin = match privilege::check_is_admin() {
        Ok(admin) => admin,
        Err(e) => {
            eprintln!("Warning: Could not check privilege level: {}", e);
            false
        }
    };

    print_intro(is_admin);

    // Collect summary for final output
    let mut summary = String::new();

    // Check processes
    println!("######################################");
    println!("[!][!][!] Checking processes [!][!][!]");
    println!("######################################\n");

    match edr_process::check_processes() {
        Ok(result) => {
            println!("{}", result);
            if result.has_detections() {
                summary.push_str("\n[!] Process Summary:\n");
                for det in &result.process_detections {
                    summary.push_str(&format!("\t[-] {} : {}\n", det.name, det.matches.join(", ")));
                }
            } else {
                summary.push_str("\n[+] No suspicious processes found\n");
            }
        }
        Err(e) => {
            println!("[-] Error checking processes: {}\n", e);
            summary.push_str("\n[-] Errored on checking processes\n");
        }
    }

    // Check current process modules
    println!("###################################################################");
    println!("[!][!][!] Checking modules loaded in your current process [!][!][!]");
    println!("###################################################################\n");

    match edr_process::check_current_process_modules() {
        Ok(result) => {
            if result.module_detections.is_empty() {
                println!("[+] No suspicious modules found in your process\n");
                summary.push_str("\n[+] No suspicious modules found in your process\n");
            } else {
                println!("[!] Modload Summary:");
                for det in &result.module_detections {
                    println!("\t[-] {} : {}", det.file_path, det.matches.join(", "));
                }
                summary.push_str("\n[!] Modload Summary:\n");
                for det in &result.module_detections {
                    summary.push_str(&format!("\t[-] {} : {}\n", det.file_path, det.matches.join(", ")));
                }
                println!();
            }
        }
        Err(e) => {
            println!("[-] Error checking modloads: {}\n", e);
            summary.push_str("\n[-] Errored on checking modloads\n");
        }
    }

    // Check directories
    println!("########################################");
    println!("[!][!][!] Checking Directories [!][!][!]");
    println!("########################################\n");

    match directory::check_directories() {
        Ok(result) => {
            if result.has_detections() {
                println!("{}", result);
                summary.push_str("\n[!] Directory Summary:\n");
                for det in &result.detections {
                    summary.push_str(&format!("\t[-] {} : {}\n", det.path.display(), det.matches.join(", ")));
                }
            } else {
                println!("{}\n", result);
                summary.push_str("\n[+] No suspicious directories found\n");
            }
        }
        Err(e) => {
            println!("[-] Error checking directories: {}\n", e);
            summary.push_str("\n[-] Errored on checking directories\n");
        }
    }

    // Check services
    println!("#####################################");
    println!("[!][!][!] Checking Services [!][!][!]");
    println!("#####################################\n");

    match service::check_services() {
        Ok(result) => {
            println!("{}", result);
            if result.has_detections() {
                summary.push_str("\n[!] Service Summary:\n");
                for det in &result.detections {
                    summary.push_str(&format!("\t[-] {} : {}\n", det.name, det.matches.join(", ")));
                }
            } else {
                summary.push_str("\n[+] No suspicious services found\n");
            }
            println!();
        }
        Err(e) => {
            println!("[-] Error checking services: {}\n", e);
            summary.push_str("\n[-] Errored on checking services\n");
        }
    }

    // Check drivers
    println!("####################################");
    println!("[!][!][!] Checking drivers [!][!][!]");
    println!("####################################\n");

    match driver::check_drivers() {
        Ok(result) => {
            println!("{}", result);
            if result.has_detections() {
                summary.push_str("\n[!] Driver Summary:\n");
                for det in &result.detections {
                    summary.push_str(&format!("\t[-] {} : {}\n", det.base_name, det.matches.join(", ")));
                }
            } else {
                summary.push_str("\n[+] No suspicious drivers found\n");
            }
            println!();
        }
        Err(e) => {
            println!("[-] Error checking drivers: {}\n", e);
            summary.push_str("\n[-] Driver checks errored\n");
        }
    }

    // Print summary
    print_outro(&summary);

    Ok(())
}

fn print_intro(is_admin: bool) {
    if is_admin {
        println!("\n##################################################################");
        println!("   [!][!][!] Welcome to SharpEDRChecker by @PwnDexter [!][!][!]");
        println!("[+][+][+] Running as admin, all checks will be performed [+][+][+]");
        println!("##################################################################\n");
    } else {
        println!("\n###################################################################################################");
        println!("                    [!][!][!] Welcome to SharpEDRChecker by @PwnDexter [!][!][!]");
        println!("[-][-][-] Not running as admin, some privileged metadata and processes may not be checked [-][-][-]");
        println!("###################################################################################################\n");
    }
}

fn print_outro(summary: &str) {
    println!("################################");
    println!("[!][!][!] TLDR Summary [!][!][!]");
    println!("################################");
    println!("{}", summary);
    println!("#######################################");
    println!("[!][!][!] EDR Checks Complete [!][!][!]");
    println!("#######################################\n");
}

