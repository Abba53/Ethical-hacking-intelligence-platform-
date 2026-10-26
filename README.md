# Ethical Hacking Intelligence Automation Platform

An AI-powered Cyber Threat Intelligence (CTI) and Ethical Hacking automation platform that combines threat intelligence collection, IOC extraction, threat scoring, AI-assisted analysis, and authorized offensive security assessments into a single modular platform.

The project is being developed incrementally through multiple phases, with a strong focus on secure architecture, modular design, asynchronous execution, and production readiness.

---

# Current Status

**Current Phase:** Phase 13 — Production Readiness Verification

Completed:
- Phases 1–10: Core platform foundations
- Phase 12: FastAPI backend implementation

In progress:
- Phase 11: AI analysis verification
- Phase 13: Production readiness verification

Upcoming:
- Web dashboard
- Mobile applications
- Production deployment verification


---

# Current Features

## Threat Intelligence

- RSS Threat Feed Collection
- ThreatFox Integration
- Chainabuse Integration
- IOC Extraction
- IOC Lookup
- IOC Correlation
- Threat Scoring

---

## Security Domains

### Network Security

- IP Reputation
- WHOIS
- AbuseIPDB
- VirusTotal
- IP Intelligence

### Blockchain Forensics

- Ethereum Wallet Investigation
- Solana Wallet Investigation
- Chainabuse Lookup

### Reconnaissance

- Subfinder
- Amass

### Network Scanning

- Nmap

### Web Security

- Nuclei
- HTTP Analysis

### Web Application Security

- ffuf
- SQLMap

### Cloud Security

- ScoutSuite (planned)

- Prowler (planned)

### Mobile Security

- MobSF (planned)

- Frida (planned)

- Objection (planned)

---

# AI Analysis

Current AI architecture supports multiple providers through a unified provider layer.

Supported providers:

- OpenAI
- Anthropic
- Google Gemini
- DeepSeek
- Local LLM
- Groq
-Cerebras
-OpenRouter
-Together
-Fireworks
-Nvidia
-Ollama
-Vllm
-Omniroute

AI capabilities include:

- Threat Analysis
- Reconnaissance Result Analysis
- Network Analysis
- Web Security Analysis
- Malware Analysis
- Executive Report Generation

---

# Telegram Bot Commands

- /start
- /status
- /feeds
- /threats
- /extract
- /lookup
- /walletinfo
- /netinfo
- /authorize
- /scan
- /auditlog
- /score
- /topthreats
- /aiscan
-/ainetwork

---

# Platform Architecture

```
Telegram Bot
        │
        ▼
Workflows
        │
        ▼
Services
        │
        ▼
Analysis
Scoring
Collectors
Extractors
Tools
        │
        ▼
SQLite Database
```

Future architecture:

```
Website
Mobile App
Telegram Bot
        │
        ▼
FastAPI Backend
        │
        ▼
Workflows
        │
        ▼
Services
        │
        ▼
Analysis
Scoring
Collectors
Extractors
Tools
        │
        ▼
Database
```

---

# Technology Stack

## Language

- Python 3.14+

## Database

- SQLite (current)
- PostgreSQL (planned for production)

## Backend

- FastAPI (planned)

## Frontend

- React + TypeScript (planned)

## Mobile

- Flutter (planned)

## AI

- OpenAI
- Anthropic
- Google Gemini
- DeepSeek
- Local LLM

## Security Tools

- Subfinder
- Amass
- Nmap
- Nuclei
- ffuf
- SQLMap
- ScoutSuite (planned)
- Prowler (planned)
- MobSF (planned)
- Frida (planned)
- Objection (planned)

---

# Design Principles

- Modular architecture
- Asynchronous execution
- SQLite-first development
- Production-ready design
- AI-assisted cybersecurity workflows
- Secure-by-default implementation
- Extensible provider architecture
- Workflow-oriented orchestration

---

# Roadmap

- Completed: Project setup, Python foundations, Telegram bot,
  threat intelligence collection, database, IOC extraction,
  security services, and threat scoring
- In progress: AI analysis verification
- Completed implementation: FastAPI backend
- In progress: Production readiness verification
- Upcoming: Web dashboard, mobile applications, production deployment

---

# API Server: Local Development

## Start the API

Run from the project root:

```bash
./venv/bin/python -m api.server
```

# License

TBD
