# Ethical Hacking Intelligence Automation Platform

An AI-powered Cyber Threat Intelligence (CTI) and Ethical Hacking automation platform that combines threat intelligence collection, IOC extraction, threat scoring, AI-assisted analysis, and authorized offensive security assessments into a single modular platform.

The project is being developed incrementally through multiple phases, with a strong focus on secure architecture, modular design, asynchronous execution, and production readiness.

---

# Current Status

**Current Phase:** Phase 11 — AI Analysis

Completed:

- ✅ Phase 1 — Project Setup
- ✅ Phase 2 — Git & GitHub
- ✅ Phase 3 — Python Foundations
- ✅ Phase 4 — Telegram Bot
- ✅ Phase 5 — RSS Threat Intelligence Collection
- ✅ Phase 6 — Threat Feed Collection
- ✅ Phase 7 — SQLite Database Layer
- ✅ Phase 8 — IOC Extraction Engine
- ✅ Phase 9 — Security Tool Integration
- ✅ Phase 10 — Threat Scoring Engine
- 🚧 Phase 11 — AI Analysis (in progress)

Upcoming:

- Phase 12 — FastAPI Backend
- Phase 13 — Web Dashboard
- Phase 14 — Authentication & RBAC
- Phase 15 — Mobile Applications
- Phase 16 — Production Deployment

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

- ✅ Project Setup
- ✅ Git & GitHub
- ✅ Python Foundations
- ✅ Telegram Bot
- ✅ RSS Collection
- ✅ Threat Feed Collection
- ✅ Database Layer
- ✅ IOC Extraction
- ✅ Security Services
- ✅ Threat Scoring
- 🚧 AI Analysis
- ⏳ FastAPI Backend
- ⏳ Web Dashboard
- ⏳ Authentication & RBAC
- ⏳ Mobile Applications
- ⏳ Production Deployment

---

# License

TBD
