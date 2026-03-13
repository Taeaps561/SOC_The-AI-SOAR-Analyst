# 🛡️ The AI-SOAR Analyst

> ⚡ Enterprise-grade Security Orchestration, Automation, and Response — powered by Local LLMs, built for real SOC workflows.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.x-00adef?logo=wazuh&logoColor=white)](https://wazuh.com/)
[![Ollama](https://img.shields.io/badge/Ollama-llama3.2-black?logo=ollama&logoColor=white)](https://ollama.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
- [Usage](#usage)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [References / Useful Resources](#references--useful-resources)

---

## Overview

**The AI-SOAR Analyst** is a fully automated, local-first Security Orchestration, Automation, and Response (SOAR) platform. It connects directly to a live **Wazuh** deployment, continuously monitors high-severity alerts, and uses a **locally-hosted LLM (Llama 3.2 via Ollama)** to perform real-time threat analysis — all without sending sensitive data to external services.

Analysts interact with the system through a purpose-built **Telegram Bot UI**, complete with rich formatting, one-click response actions, and raw log inspection. High-confidence threats are escalated automatically.

> 🔗 Demo on YouTube: *(link coming soon)*
> 📦 Open-source | `the-ai-soar-analyst`

---

## Key Features

| Feature | Description |
|---|---|
| 🔴 Real-time Monitoring | Continuously polls Wazuh Indexer for high-severity security events |
| 🤖 Local AI Analysis | Uses Llama 3.2 (3B) via native Ollama SDK — fully offline, fully private |
| 📲 Telegram SOAR UI | Richly formatted alerts with hashtags, monospaced text, and interactive buttons |
| 🛡️ Acknowledge Alert | Instantly mark alerts as seen and update the audit trail |
| 🚫 Block IP | Trigger Wazuh Active Response to ban malicious source IPs |
| 🔍 View Full Log | Retrieve raw JSON metadata directly in Telegram for deep-dive analysis |
| ⚡ Auto-Escalation | High-confidence threats (>90% AI score) trigger immediate host isolation |
| 📋 Audit Logging | Full decision trail written to `logs/actions.log` with UTF-8 support |

---

## Architecture

The system uses a modular Python architecture designed for clarity and extensibility:

```
                 ┌─────────────────────────────────────────────┐
                 │              Wazuh Deployment                │
                 │   Manager :55000        Indexer :9200        │
                 └──────────────┬──────────────────────────────┘
                                │ Alerts (REST API)
                                ▼
                 ┌─────────────────────────────────────────────┐
                 │           main.py  (Orchestrator)            │
                 │   High-frequency polling + event dispatcher  │
                 └──────────┬─────────────────┬────────────────┘
                            │                 │
              ┌─────────────▼───┐   ┌─────────▼──────────────┐
              │  wazuh_client   │   │      ai_engine          │
              │  (Dual-port     │   │  (Ollama / llama3.2     │
              │   integration)  │   │   JSON-enforced output) │
              └─────────────────┘   └────────────┬───────────┘
                                                 │ AI Decision
                                    ┌────────────▼───────────┐
                                    │       responder         │
                                    │  Telegram Bot Handler   │
                                    │  + Active Response Mgr  │
                                    └────────────────────────┘
```

### Module Responsibilities

- **`main.py`** — Orchestrator. Runs the high-frequency Telegram update polling loop and coordinates all modules.
- **`modules/wazuh_client.py`** — Handles dual-port integration with the Wazuh Manager (`:55000`) and Indexer (`:9200`).
- **`modules/ai_engine.py`** — Native Ollama integration with deterministic JSON output enforcement for structured threat scoring.
- **`modules/responder.py`** — Telegram Bot interaction handler, alert formatter, and SOAR decision logic.

---

## Tech Stack

| Layer | Technology |
|---|---|
| SIEM / EDR | [Wazuh](https://wazuh.com/) 4.x |
| Local LLM | [Ollama](https://ollama.com/) + `llama3.2:3b` |
| Notification | [Telegram Bot API](https://core.telegram.org/bots/api) |
| Runtime | Python 3.10+ |
| Search Backend | Wazuh Indexer (Elasticsearch-compatible, port 9200) |
| Active Response | Wazuh Manager REST API (port 55000) |

---

## Getting Started

### Prerequisites

Before running the project, ensure the following services are available and accessible:

- ✅ **Wazuh**: Manager and Indexer installed, running, and reachable on your network
- ✅ **Ollama**: Local service running with the `llama3.2` model pulled
- ✅ **Python 3.10+**: Installed on the host machine
- ✅ **Telegram Bot**: Created via [@BotFather](https://t.me/BotFather) with a valid token and chat ID

```bash
# Pull the required model into Ollama
ollama pull llama3.2
```

---

### Installation

```bash
# 1. Clone the repository
git clone <repository-url>
cd "SOC_The AI_SOAR Analyst"

# 2. Install Python dependencies
pip install -r requirements.txt
```

---

### Configuration

Copy the example environment file and fill in your credentials:

```bash
cp .env.example .env
```

Edit `.env` with your environment values:

```env
# Wazuh
WAZUH_HOST=https://<wazuh-manager-ip>:55000
WAZUH_INDEXER_HOST=https://<indexer-ip>:9200
WAZUH_USER=your-username
WAZUH_PASSWORD=your-password

# Telegram
TELEGRAM_BOT_TOKEN=your-bot-token
TELEGRAM_CHAT_ID=your-chat-id

# AI Engine
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2
```

> ⚠️ **Security Note:** Never commit your `.env` file. It is already included in `.gitignore`.

---

## Usage

```bash
# Start the AI-SOAR Analyst
python main.py
```

Once running, the bot will:

1. Connect to Wazuh and begin polling for alerts with severity ≥ 10
2. Send each alert to Ollama for AI-powered threat analysis
3. Deliver a formatted alert card to your Telegram chat
4. Wait for your interactive response — or auto-escalate if AI confidence > 90%

---

## Testing

```bash
# Run unit tests
python -m pytest tests/

# Run AI stress test (validates Ollama JSON output stability)
python scripts/stress_test_ai.py

# Run live simulation demo (no real Wazuh required)
python scripts/live_demo.py
```

---

## Project Structure

```
SOC_The AI_SOAR Analyst/
│
├── main.py                   # Orchestrator — entry point
├── requirements.txt
├── .env.example
│
├── modules/
│   ├── wazuh_client.py       # Wazuh Manager + Indexer integration
│   ├── ai_engine.py          # Ollama / LLM threat analysis engine
│   └── responder.py          # Telegram bot + SOAR response logic
│
├── scripts/
│   ├── stress_test_ai.py     # AI output reliability testing
│   └── live_demo.py          # Simulated alert demo
│
├── tests/
│   └── ...                   # Unit tests
│
└── logs/
    └── actions.log           # Audit trail (UTF-8)
```

---

## References / Useful Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Ollama API Reference](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [Telegram Bot API](https://core.telegram.org/bots/api)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## My Notes

> 📝 This project was built as a hands-on learning exercise in AI-assisted SOC workflows, combining SIEM integration, local LLM inference, and interactive chatbot-based SOAR response. Contributions and feedback are welcome.

---

## License

MIT License. Created for SOC Analysts by **The AI-SOAR Team**.

---

*Built with ❤️ for defenders, by defenders.*
