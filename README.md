# 🛡️ The AI-SOAR Analyst

**The AI-SOAR Analyst** is an enterprise-grade Security Orchestration, Automation, and Response (SOAR) tool. It leverages Local LLMs (via Ollama) to analyze security alerts from Wazuh in real-time and provides interactive response capabilities through Telegram.

## 🚀 Features
- **Real-time Monitoring**: Continuous polling of Wazuh Indexer for high-severity security events.
- **Local AI Analysis**: Uses Llama 3.2 (3B) via native Ollama SDK for private, offline threat intelligence.
- **Enterprise Telegram UI**: Richly formatted alerts with hashtags, monospaced text for copy-pasting, and interactive buttons.
- **Interactive SOAR**: 
    - 🛡️ **Acknowledge**: Instantly mark alerts as seen.
    - 🚫 **Block IP**: Trigger active response to ban malicious IPs.
    - 🔍 **View Full Log**: Retrieve raw JSON metadata directly in chat for deep-dive analysis.
- **Automated Actions**: High-confidence threats (>90%) trigger immediate host isolation.
- **Audit Logging**: Comprehensive decision trail in `logs/actions.log` with UTF-8 support.

## 🏗️ Architecture
The system is built with a modular Python architecture:
- `main.py`: Orchestrator with high-frequency Telegram update polling.
- `modules/wazuh_client.py`: Dual-port integration (Manager 55000 & Indexer 9200).
- `modules/ai_engine.py`: Native Ollama integration with deterministic JSON enforcement.
- `modules/responder.py`: Telegram Bot interaction handler and decision logic.

## 🛠️ Installation

### 1. Prerequisites
- **Wazuh**: Manager and Indexer installed and accessible.
- **Ollama**: Local service running with `llama3.2` model pulled (`ollama pull llama3.2`).
- **Python 3.10+**

### 2. Setup
```powershell
# Clone the repository
git clone <repository-url>
cd "SOC_The AI_SOAR Analyst"

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration
Copy `.env.example` to `.env` and fill in your credentials:
```text
WAZUH_HOST=https://<wazuh-ip>:55000
WAZUH_INDEXER_HOST=https://<indexer-ip>:9200
TELEGRAM_BOT_TOKEN=your-token
TELEGRAM_CHAT_ID=your-id
```

## 🧪 Testing
```powershell
# Run unit tests
python -m pytest tests/

# Run AI Stress Test
python scripts/stress_test_ai.py

# Run Live Simulation Demo
python scripts/live_demo.py
```

## 📄 License
MIT License. Created for SOC Analysts by The AI-SOAR Team.
