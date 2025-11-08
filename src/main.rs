//! SharpEDRChecker binary entry point

use clap::Parser;
use serde::Serialize;
use sharp_edr_checker::{directory, driver, privilege, registry, service};
use sharp_edr_checker::process as edr_process;

/// EDR/AV/logging tool detection for authorized security assessments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Output results in JSON format
    #[arg(short, long)]
    json: bool,
}

/// Combined results from all detection checks
#[derive(Debug, Serialize)]
struct ScanResults {
    is_admin: bool,
    processes: Option<edr_process::CheckResult>,
    modules: Option<edr_process::CheckResult>,
    directories: Option<directory::CheckResult>,
    registry: Option<registry::CheckResult>,
    services: Option<service::CheckResult>,
    drivers: Option<driver::CheckResult>,
    errors: Vec<String>,
}

impl ScanResults {
    fn new(is_admin: bool) -> Self {
        Self {
            is_admin,
            processes: None,
            modules: None,
            directories: None,
            registry: None,
            services: None,
            drivers: None,
            errors: Vec::new(),
        }
    }
}

fn main() {
    let args = Args::parse();

    if let Err(e) = run(args.json) {
        eprintln!("[-] Error running SharpEDRChecker: {}", e);
        std::process::exit(1);
    }
}

fn run(json_output: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Check privilege level
    let is_admin = match privilege::check_is_admin() {
        Ok(admin) => admin,
        Err(e) => {
            if !json_output {
                eprintln!("Warning: Could not check privilege level: {}", e);
            }
            false
        }
    };

    let mut results = ScanResults::new(is_admin);

    if !json_output {
        print_intro(is_admin);
    }

    // Collect summary for text output
    let mut summary = String::new();

    // Check processes
    if !json_output {
        println!("######################################");
        println!("[!][!][!] Checking processes [!][!][!]");
        println!("######################################\n");
    }

    match edr_process::check_processes() {
        Ok(result) => {
            if !json_output {
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
            results.processes = Some(result);
        }
        Err(e) => {
            let err_msg = format!("Error checking processes: {}", e);
            if !json_output {
                println!("[-] {}\n", err_msg);
                summary.push_str("\n[-] Errored on checking processes\n");
            }
            results.errors.push(err_msg);
        }
    }

    // Check current process modules
    if !json_output {
        println!("###################################################################");
        println!("[!][!][!] Checking modules loaded in your current process [!][!][!]");
        println!("###################################################################\n");
    }

    match edr_process::check_current_process_modules() {
        Ok(result) => {
            if !json_output {
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
            results.modules = Some(result);
        }
        Err(e) => {
            let err_msg = format!("Error checking modloads: {}", e);
            if !json_output {
                println!("[-] {}\n", err_msg);
                summary.push_str("\n[-] Errored on checking modloads\n");
            }
            results.errors.push(err_msg);
        }
    }

    // Check directories
    if !json_output {
        println!("########################################");
        println!("[!][!][!] Checking Directories [!][!][!]");
        println!("########################################\n");
    }

    match directory::check_directories() {
        Ok(result) => {
            if !json_output {
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
            results.directories = Some(result);
        }
        Err(e) => {
            let err_msg = format!("Error checking directories: {}", e);
            if !json_output {
                println!("[-] {}\n", err_msg);
                summary.push_str("\n[-] Errored on checking directories\n");
            }
            results.errors.push(err_msg);
        }
    }

    // Check registry
    if !json_output {
        println!("####################################");
        println!("[!][!][!] Checking Registry [!][!][!]");
        println!("####################################\n");
    }

    match registry::check_registry() {
        Ok(result) => {
            if !json_output {
                println!("{}", result);
                if result.has_detections() {
                    summary.push_str("\n[!] Registry Summary:\n");
                    for det in &result.detections {
                        summary.push_str(&format!("\t[-] {} : {}\n", det.key_path, det.matches.join(", ")));
                    }
                } else {
                    summary.push_str("\n[+] No suspicious registry entries found\n");
                }
                println!();
            }
            results.registry = Some(result);
        }
        Err(e) => {
            let err_msg = format!("Error checking registry: {}", e);
            if !json_output {
                println!("[-] {}\n", err_msg);
                summary.push_str("\n[-] Errored on checking registry\n");
            }
            results.errors.push(err_msg);
        }
    }

    // Check services
    if !json_output {
        println!("#####################################");
        println!("[!][!][!] Checking Services [!][!][!]");
        println!("#####################################\n");
    }

    match service::check_services() {
        Ok(result) => {
            if !json_output {
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
            results.services = Some(result);
        }
        Err(e) => {
            let err_msg = format!("Error checking services: {}", e);
            if !json_output {
                println!("[-] {}\n", err_msg);
                summary.push_str("\n[-] Errored on checking services\n");
            }
            results.errors.push(err_msg);
        }
    }

    // Check drivers
    if !json_output {
        println!("####################################");
        println!("[!][!][!] Checking drivers [!][!][!]");
        println!("####################################\n");
    }

    match driver::check_drivers() {
        Ok(result) => {
            if !json_output {
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
            results.drivers = Some(result);
        }
        Err(e) => {
            let err_msg = format!("Error checking drivers: {}", e);
            if !json_output {
                println!("[-] {}\n", err_msg);
                summary.push_str("\n[-] Driver checks errored\n");
            }
            results.errors.push(err_msg);
        }
    }

    // Output results
    if json_output {
        let json = serde_json::to_string_pretty(&results)?;
        println!("{}", json);
    } else {
        print_outro(&summary);
    }

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
