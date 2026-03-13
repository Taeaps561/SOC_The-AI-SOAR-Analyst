import sys
import os
import json
import logging
from dotenv import load_dotenv

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.ai_engine import AIEngine
from tabulate import tabulate

# Load environment variables
load_dotenv()

# Configure logging to be quiet for the script
logging.basicConfig(level=logging.ERROR)

def run_stress_test():
    # Initialize AI Engine
    ai_engine = AIEngine(
        api_key=os.getenv("OPENAI_API_KEY", "ollama"),
        model=os.getenv("OLLAMA_MODEL", "llama3.2"),
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    )

    # 1. Mock Data Scenarios
    scenarios = [
        {
            "name": "True Positive (SQL Injection)",
            "log": {
                "agent": {"id": "001", "name": "web-server"},
                "rule": {"description": "Web attack: SQL Injection attempt"},
                "full_log": "GET /products.php?id=1 UNION SELECT username, password FROM users--",
                "decoder": {"name": "web-accesslog"},
                "data": {"url": "/products.php?id=1 UNION SELECT username, password FROM users--"}
            }
        },
        {
            "name": "False Positive (Admin Action)",
            "log": {
                "agent": {"id": "002", "name": "db-admin"},
                "rule": {"description": "System file access: /etc/passwd"},
                "full_log": "Mar 13 10:40:01 db-admin sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/cat /etc/passwd",
                "data": {"user": "admin", "command": "/usr/bin/cat /etc/passwd"}
            }
        },
        {
            "name": "Ambiguous Log (Incomplete)",
            "log": {
                "agent": {"id": "003", "name": "unknown-agent"},
                "rule": {"description": "Multiple errors"},
                "data": {}
            }
        }
    ]

    results = []

    print("\nStarting Adversarial AI Stress Test...\n")

    for scenario in scenarios:
        print(f"Testing: {scenario['name']}...")
        analysis = ai_engine.analyze_alert(scenario['log'])
        
        results.append([
            scenario['name'],
            analysis.get('confidence_score', 'N/A'),
            analysis.get('threat_category', 'N/A'),
            analysis.get('recommended_action', 'N/A'),
            analysis.get('reasoning', 'N/A')[:100] + "..." if len(analysis.get('reasoning', '')) > 100 else analysis.get('reasoning', 'N/A')
        ])

    # Print Table
    headers = ["Scenario", "Confidence", "Category", "Action", "Reasoning"]
    print("\n" + tabulate(results, headers=headers, tablefmt="grid"))
    print("\n[DONE] Stress Test Completed.")

if __name__ == "__main__":
    run_stress_test()
