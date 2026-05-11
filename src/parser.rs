// parser.rs — Reads and parses log files into ThreatEvents

use std::fs;
use crate::models::{ThreatEvent, Severity};

pub fn parse_log_file(path: &str) -> Result<Vec<ThreatEvent>, String> {
    // Try to read the file — if it fails, return an error
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Could not read log file '{}': {}", path, e))?;

    let mut threats: Vec<ThreatEvent> = Vec::new();
    let mut id = 1;

    for line in content.lines() {
        let line_lower = line.to_lowercase();

        // Detect failed SSH login
        if line_lower.contains("failed password") {
            threats.push(ThreatEvent {
                id,
                source_ip: extract_ip(line).unwrap_or_else(|| "unknown".to_string()),
                severity: Severity::High,
                description: String::from("Failed SSH login attempt detected"),
            });
            id += 1;
        }

        // Detect port scan
        else if line_lower.contains("portscan") {
            threats.push(ThreatEvent {
                id,
                source_ip: extract_ip(line).unwrap_or_else(|| "unknown".to_string()),
                severity: Severity::Critical,
                description: String::from("Port scan detected"),
            });
            id += 1;
        }

        // Detect firewall block
        else if line_lower.contains("blocked connection") {
            threats.push(ThreatEvent {
                id,
                source_ip: extract_ip(line).unwrap_or_else(|| "unknown".to_string()),
                severity: Severity::Medium,
                description: String::from("Firewall blocked connection"),
            });
            id += 1;
        }

        // Detect sudo failure
        else if line_lower.contains("authentication failure") {
            threats.push(ThreatEvent {
                id,
                source_ip: None.unwrap_or_else(|| "local".to_string()),
                severity: Severity::Low,
                description: String::from("Sudo authentication failure"),
            });
            id += 1;
        }
    }

    Ok(threats)
}

// Extract first IP address found in a log line
fn extract_ip(line: &str) -> Option<String> {
    for word in line.split_whitespace() {
        let clean = word.trim_end_matches(|c: char| !c.is_numeric());
        let parts: Vec<&str> = clean.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            return Some(clean.to_string());
        }
    }
    None
}
