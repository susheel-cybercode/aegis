// detector.rs — Threat detection, scoring, and colored output

use colored::*;
use crate::models::{ThreatEvent, Severity};

pub fn print_alert(threat: &ThreatEvent) {
    println!("{}", "─────────────────────────────────────".bright_black());

    let severity_label = match &threat.severity {
        Severity::Critical => "CRITICAL".red().bold(),
        Severity::High     => "HIGH".truecolor(255, 140, 0).bold(),
        Severity::Medium   => "MEDIUM".yellow().bold(),
        Severity::Low      => "LOW".cyan().bold(),
    };

    println!("🚨 {} [{}]", 
        format!("THREAT #{}", threat.id).white().bold(),
        severity_label
    );
    println!("   {} {}",
        "IP:".bright_black(),
        threat.source_ip.cyan()
    );
    println!("   {} {}",
        "Description:".bright_black(),
        threat.description.white()
    );
}

pub fn risk_score(threat: &ThreatEvent) -> u8 {
    match &threat.severity {
        Severity::Critical => 95,
        Severity::High     => 75,
        Severity::Medium   => 50,
        Severity::Low      => 20,
    }
}

pub fn print_risk_score(score: u8) {
    let colored_score = match score {
        0..=30  => format!("{}/100", score).green().bold(),
        31..=60 => format!("{}/100", score).yellow().bold(),
        61..=80 => format!("{}/100", score).truecolor(255, 140, 0).bold(),
        _       => format!("{}/100", score).red().bold(),
    };
    println!("   {} {}", "Risk Score:".bright_black(), colored_score);
}

pub fn print_banner() {
    println!("{}", "
 █████╗ ███████╗ ██████╗ ██╗███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
███████║█████╗  ██║  ███╗██║███████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║
██║  ██║███████╗╚██████╔╝██║███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝"
    .red().bold());
    println!("{}", 
        "  AI-Powered Security Intelligence Platform | v0.1.0"
        .bright_white()
    );
    println!("{}\n", 
        "  Rust 🦀 + AI 🤖 + Cybersecurity 🔐"
        .bright_black()
    );
}

pub fn print_section(title: &str) {
    println!("\n{}", "─────────────────────────────────────".bright_black());
    println!("{}", format!("  {}", title).bright_white().bold());
    println!("{}", "─────────────────────────────────────".bright_black());
}

pub fn print_ai_analysis(analysis: &str) {
    for line in analysis.lines() {
        if line.starts_with("**") && line.ends_with("**") {
            println!("{}", line.replace("**", "").bright_yellow().bold());
        } else if line.starts_with("1.") || line.starts_with("2.") 
               || line.starts_with("3.") || line.starts_with("4.")
               || line.starts_with("5.") {
            println!("{}", line.bright_white());
        } else {
            println!("{}", line.white());
        }
    }
}
