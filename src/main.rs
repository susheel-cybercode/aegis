// main.rs — AEGIS entry point

mod models;
mod detector;
mod parser;
mod hunter;
mod ai_analyst;
mod shield;
mod api;

use colored::Colorize;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    // Banner
    detector::print_banner();

    // --- HUNTER ENGINE ---
    detector::print_section("🔍 HUNTER ENGINE — Brute Force Detection");
    match hunter::detect_brute_force("logs/sample.log") {
        Ok(threats) => {
            if threats.is_empty() {
                println!("{}", "  ✅ No brute force attacks detected.".green());
            } else {
                for threat in &threats {
                    detector::print_alert(threat);
                    detector::print_risk_score(detector::risk_score(threat));
                }
                println!("\n{}",
                    format!("  🚨 {} brute force attack(s) detected.", threats.len())
                    .red().bold()
                );
            }
        }
        Err(e) => println!("{}", format!("  ❌ Error: {}", e).red()),
    }

    // --- FULL LOG ANALYSIS ---
    detector::print_section("📂 FULL LOG ANALYSIS");
    match parser::parse_log_file("logs/sample.log") {
        Ok(threats) => {
            for threat in &threats {
                detector::print_alert(threat);
                detector::print_risk_score(detector::risk_score(threat));
            }
            println!("\n{}",
                format!("  ✅ {} total threats analyzed.", threats.len())
                .green().bold()
            );

            // --- AI ANALYSIS ---
            detector::print_section("🤖 AI THREAT ANALYSIS");
            println!("{}", "  Sending threats to AI analyst...\n".bright_black());
            match ai_analyst::analyze_threats(&threats).await {
                Ok(analysis) => detector::print_ai_analysis(&analysis),
                Err(e) => println!("{}", format!("  ❌ AI analysis failed: {}", e).red()),
            }
        }
        Err(e) => println!("{}", format!("  ❌ Error: {}", e).red()),
    }

    // --- SHIELD ENGINE ---
    detector::print_section("🛡️  SHIELD ENGINE — AI Security");
    shield::run_shield_demo();

    // --- REST API ---
    detector::print_section("🌐 REST API — Starting Server");
    let router = api::create_router("logs/sample.log".to_string());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();

    println!("{}", "  AEGIS API is running!\n".green().bold());
    println!("  {} http://localhost:8080/health",  "GET ".cyan().bold());
    println!("  {} http://localhost:8080/analyze", "GET ".cyan().bold());
    println!("  {} http://localhost:8080/shield",  "POST".cyan().bold());
    println!("\n{}", "  Press Ctrl+C to stop.".bright_black());

    axum::serve(listener, router).await.unwrap();
}
