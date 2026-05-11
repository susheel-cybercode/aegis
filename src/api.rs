// api.rs — AEGIS REST API endpoints

use axum::{
    routing::{get, post},
    Router,
    Json,
    extract::State,
};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use crate::models::{HealthResponse, ShieldRequest};
use crate::shield::{analyze_input, ShieldVerdict};
use crate::parser::parse_log_file;
use crate::models::ThreatEvent;

// Shared app state
pub struct AppState {
    pub log_path: String,
}

// Response types
#[derive(Serialize)]
pub struct ShieldResponse {
    pub verdict: String,
    pub reason: String,
    pub confidence: u8,
    pub blocked: bool,
}

#[derive(Serialize)]
pub struct AnalyzeResponse {
    pub total_threats: usize,
    pub threats: Vec<ThreatEvent>,
}

// GET /health
pub async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "operational".to_string(),
        version: "0.1.0".to_string(),
        engines: vec![
            "HUNTER — Threat Detection".to_string(),
            "SHIELD — AI Security".to_string(),
        ],
    })
}

// GET /analyze
pub async fn analyze_handler(
    State(state): State<Arc<AppState>>,
) -> Json<AnalyzeResponse> {
    match parse_log_file(&state.log_path) {
        Ok(threats) => Json(AnalyzeResponse {
            total_threats: threats.len(),
            threats,
        }),
        Err(_) => Json(AnalyzeResponse {
            total_threats: 0,
            threats: vec![],
        }),
    }
}

// POST /shield
pub async fn shield_handler(
    Json(payload): Json<ShieldRequest>,
) -> Json<ShieldResponse> {
    let result = analyze_input(&payload.input);

    let blocked = matches!(result.verdict, ShieldVerdict::Blocked);
    let verdict = match result.verdict {
        ShieldVerdict::Blocked    => "BLOCKED",
        ShieldVerdict::Suspicious => "SUSPICIOUS",
        ShieldVerdict::Safe       => "SAFE",
    };

    Json(ShieldResponse {
        verdict: verdict.to_string(),
        reason: result.reason,
        confidence: result.confidence,
        blocked,
    })
}

// Build the router
pub fn create_router(log_path: String) -> Router {
    let state = Arc::new(AppState { log_path });

    Router::new()
        .route("/health",  get(health_handler))
        .route("/analyze", get(analyze_handler))
        .route("/shield",  post(shield_handler))
        .with_state(state)
}
