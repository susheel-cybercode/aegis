// models.rs — All data structures for AEGIS

use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: u32,
    pub source_ip: String,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShieldRequest {
    pub input: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub engines: Vec<String>,
}
