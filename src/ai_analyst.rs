// ai_analyst.rs — Groq API integration (free)

use crate::models::ThreatEvent;

pub async fn analyze_threats(threats: &[ThreatEvent]) -> Result<String, String> {
    let api_key = std::env::var("GROQ_API_KEY")
        .map_err(|_| "GROQ_API_KEY not set in .env file".to_string())?;

    let threat_summary = build_threat_summary(threats);

    let body = serde_json::json!({
        "model": "llama-3.3-70b-versatile",
        "max_tokens": 1024,
        "messages": [
            {
                "role": "system",
                "content": "You are a senior cybersecurity analyst. Analyze the threat data and provide: 1) THREAT ASSESSMENT 2) ATTACK PATTERN ANALYSIS 3) RECOMMENDED ACTIONS. Be concise and technical."
            },
            {
                "role": "user",
                "content": format!(
                    "Analyze these security threats detected by AEGIS:\n\n{}",
                    threat_summary
                )
            }
        ]
    });

    let client = reqwest::Client::new();
    let response = client
        .post("https://api.groq.com/openai/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("API request failed: {}", e))?;

    let status = response.status();
    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if !status.is_success() {
        return Err(format!("API error: {}", json["error"]["message"]
            .as_str().unwrap_or("Unknown error")));
    }

    let analysis = json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("No analysis returned")
        .to_string();

    Ok(analysis)
}

fn build_threat_summary(threats: &[ThreatEvent]) -> String {
    let lines: Vec<String> = threats
        .iter()
        .map(|t| format!(
            "- [{:?}] IP: {} | {}",
            t.severity, t.source_ip, t.description
        ))
        .collect();

    format!(
        "Total threats: {}\n\n{}",
        threats.len(),
        lines.join("\n")
    )
}
