# 🦀 AEGIS — AI-Powered Security Intelligence Platform

> Autonomous security platform built entirely in **Rust** with dual engines for threat detection and AI defense.

![Rust](https://img.shields.io/badge/Rust-1.95-orange?logo=rust)
![AI](https://img.shields.io/badge/AI-Groq%20LLM-blue)
![Security](https://img.shields.io/badge/Security-CEH-red)

---

## 🏗️ Architecture

```
AEGIS
├── HUNTER Engine  → Detects threats in security logs using pattern analysis + AI
└── SHIELD Engine  → Protects AI systems from prompt injection and jailbreaks
```

## ⚙️ Tech Stack

| Layer | Technology |
|---|---|
| Core language | Rust 1.95 |
| Async runtime | Tokio |
| Web framework | Axum |
| AI integration | Groq API (Llama 3.3 70B) |
| Serialization | Serde + serde_json |
| HTTP client | Reqwest |

## 🔍 HUNTER Engine

- Brute force SSH attack detection (HashMap IP aggregation)
- Port scan detection
- Firewall block analysis
- Sudo escalation attempts
- AI-generated incident reports via LLM

## 🛡️ SHIELD Engine

- Prompt injection detection
- Jailbreak attempt classification
- Sensitive data leak prevention
- Confidence scoring per detection

## 🌐 REST API

| Method | Endpoint | Description |
|---|---|---|
| GET | /health | Platform status |
| GET | /analyze | Run HUNTER on logs |
| POST | /shield | Scan input with SHIELD |

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/susheel-cybercode/aegis
cd aegis

# Add your free Groq API key (console.groq.com)
echo "GROQ_API_KEY=your_key_here" > .env

# Run AEGIS
cargo run
```

## 📁 Project Structure

```
aegis/
├── src/
│   ├── main.rs         # Entry point + async runtime
│   ├── models.rs       # Data structures (Serde)
│   ├── detector.rs     # Colored output + risk scoring
│   ├── parser.rs       # Log file parser
│   ├── hunter.rs       # Brute force detection (HashMap)
│   ├── ai_analyst.rs   # LLM API integration
│   ├── shield.rs       # AI attack detection
│   └── api.rs          # Axum REST endpoints
├── logs/
│   └── sample.log
├── .env.example
├── Cargo.toml
└── README.md
```

## 🦀 Rust Concepts Demonstrated

- Structs, Enums, Pattern matching
- Ownership, Borrowing, Lifetimes
- Async/Await with Tokio
- Error handling with Result
- HashMap aggregation
- Modular architecture (8 modules)
- REST API with Axum
- JSON serialization with Serde
- Shared state with Arc

## 👤 Author

**Susheel M S** — AI + Rust Developer | CEH Certified

[GitHub](https://github.com/susheel-cybercode)
