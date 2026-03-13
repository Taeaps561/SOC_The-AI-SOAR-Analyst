import os
import sys
import json
import time
import logging
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.ai_engine import AIEngine
from modules.responder import Responder

# Load environment
load_dotenv()

# Configure logging for demo
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [DEMO] - %(levelname)s - %(message)s'
)
logger = logging.getLogger("RealTimeDemo")

class MockWazuhClient:
    """Simulates a Wazuh Indexer that 'finds' new alerts over time."""
    def __init__(self):
        self.all_alerts = [
            {
                "id": "demo-001",
                "@timestamp": datetime.now().isoformat(),
                "agent": {"id": "web-01", "name": "web-production"},
                "rule": {"id": "100101", "level": 10, "description": "Web attack: SQL Injection (UNION SELECT)"},
                "data": {"srcip": "1.2.3.4"},
                "full_log": "GET /api/users?id=1 UNION SELECT null,null,username,password FROM users--"
            },
            {
                "id": "demo-002",
                "@timestamp": (datetime.now() + timedelta(seconds=1)).isoformat(),
                "agent": {"id": "db-01", "name": "database-main"},
                "rule": {"id": "5712", "level": 12, "description": "Brute force attack: multiple login failures"},
                "data": {"srcip": "192.168.1.105"},
                "full_log": "Mar 13 14:00:01 db-01 sshd[123]: Failed password for root from 192.168.1.105 port 1234 ssh2"
            }
        ]
        self.alerts_queue = []
        self.token = "fake-demo-token"

    def get_token(self):
        return self.token

    def get_latest_alerts(self, min_level=7, limit=10):
        # Return currently 'discovered' alerts
        return self.alerts_queue

    def get_alert_by_id(self, alert_id):
        """Mock version of fetching alert from Indexer."""
        for a in self.all_alerts:
            if a['id'] == alert_id:
                return a
        return None

def run_live_demo():
    logger.info("Starting REAL-TIME SOAR DEMO...")
    logger.info("This will simulate alert discovery, AI analysis, and Telegram notification.")

    # Initialize Real Modules (except Wazuh)
    wazuh_mock = MockWazuhClient()
    
    ai_engine = AIEngine(
        model=os.getenv("OLLAMA_MODEL", "llama3.2"),
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    )
    
    responder = Responder(
        wazuh_client=wazuh_mock,
        telegram_token=os.getenv("TELEGRAM_BOT_TOKEN"),
        telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID")
    )

    last_processed_timestamp = None
    demo_queue = wazuh_mock.all_alerts.copy()
    
    # Start Simulation Loop
    try:
        current_step = 0
        while current_step < len(demo_queue) + 1:
            logger.info("--- Polling Indexer for new alerts ---")
            
            # Simulate a new alert arriving in the indexer
            if current_step < len(demo_queue):
                new_alert = demo_queue[current_step]
                wazuh_mock.alerts_queue = [new_alert]
                logger.info(f"Indexer discovered NEW alert: {new_alert['id']}")
            else:
                wazuh_mock.alerts_queue = []
                logger.info("No new alerts on Indexer.")

            # Logic from main.py
            if wazuh_mock.get_token():
                alerts = wazuh_mock.get_latest_alerts()
                
                for alert in alerts:
                    alert_time = alert.get('@timestamp')
                    
                    if last_processed_timestamp and alert_time <= last_processed_timestamp:
                        continue
                    
                    logger.info(f"Analysing Alert {alert['id']} with Local AI...")
                    analysis = ai_engine.analyze_alert(alert)
                    logger.info(f"AI Verdict: {analysis.get('threat_category')} - Confidence: {analysis.get('confidence_score')}%")
                    
                    logger.info("Executing Responder logic...")
                    responder.process_recommendation(analysis, alert)
                    
                    last_processed_timestamp = alert_time

            current_step += 1
            if current_step <= len(demo_queue):
                logger.info("Waiting 10 seconds for next poll simulation (You can click buttons in Telegram now!)...")
                # Poll for button clicks during the wait time
                wait_start = time.time()
                while time.time() - wait_start < 10:
                    responder.check_for_telegram_updates()
                    time.sleep(1)

    except KeyboardInterrupt:
        logger.info("Demo stopped.")

    logger.info("--- DEMO COMPLETED ---")
    logger.info("Verify your Telegram to see the notifications sent during this demo.")

if __name__ == "__main__":
    run_live_demo()
