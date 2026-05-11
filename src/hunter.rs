// hunter.rs — AEGIS HUNTER engine
// Detects attack patterns using HashMap aggregation

use std::collections::HashMap;
use crate::models::{ThreatEvent, Severity};

pub fn detect_brute_force(log_path: &str) -> Result<Vec<ThreatEvent>, String> {
    let content = std::fs::read_to_string(log_path)
        .map_err(|e| format!("Cannot read log file: {}", e))?;

    // Count failed logins per IP using HashMap
    let mut fail_counts: HashMap<String, u32> = HashMap::new();

    for line in content.lines() {
        if line.to_lowercase().contains("failed password") {
            if let Some(ip) = extract_ip(line) {
                // entry() gets existing value or inserts 0, then adds 1
                *fail_counts.entry(ip).or_insert(0) += 1;
            }
        }
    }

    // Build threat events only for IPs with 3+ failures
    let mut threats: Vec<ThreatEvent> = Vec::new();
    let mut id = 1;

    for (ip, count) in &fail_counts {
        if *count >= 3 {
            let severity = match count {
                3..=9  => Severity::High,
                10..=49 => Severity::Critical,
                _       => Severity::Critical,
            };

            threats.push(ThreatEvent {
                id,
                source_ip: ip.clone(),
                severity,
                description: format!(
                    "Brute force detected — {} failed login attempts", count
                ),
            });
            id += 1;
        }
    }

    Ok(threats)
}

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
