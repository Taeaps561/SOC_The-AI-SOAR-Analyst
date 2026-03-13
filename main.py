import os
import logging
import json
from dotenv import load_dotenv
from modules.wazuh_client import WazuhClient
from modules.ai_engine import AIEngine
from modules.responder import Responder

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/app.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Orchestrator")

import time

def main():
    logger.info("Starting The AI-SOAR Analyst (Real-time Mode)...")

    # Initialize Modules
    wazuh = WazuhClient(
        host=os.getenv("WAZUH_HOST"),
        user=os.getenv("WAZUH_USER"),
        password=os.getenv("WAZUH_PASSWORD"),
        indexer_host=os.getenv("WAZUH_INDEXER_HOST"),
        indexer_user=os.getenv("WAZUH_INDEXER_USER"),
        indexer_password=os.getenv("WAZUH_INDEXER_PASSWORD")
    )
    
    ai_engine = AIEngine(
        model=os.getenv("OLLAMA_MODEL", "llama3.2"),
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    )
    
    responder = Responder(
        wazuh_client=wazuh,
        telegram_token=os.getenv("TELEGRAM_BOT_TOKEN"),
        telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID")
    )

    poll_interval = int(os.getenv("POLL_INTERVAL", 60))
    last_processed_timestamp = None

    # Persistent Monitoring Loop
    try:
        while True:
            if wazuh.get_token():
                # Fetch alerts
                alerts = wazuh.get_latest_alerts(min_level=7, limit=10)
                
                # Reverse alerts to process oldest first if needed, 
                # but usually we just want to find new ones.
                new_alerts_found = 0
                for alert in alerts:
                    alert_time = alert.get('@timestamp')
                    
                    # If we've seen this alert time or older, skip (Alerts are sorted desc)
                    if last_processed_timestamp and alert_time <= last_processed_timestamp:
                        continue
                    
                    logger.info(f"Processing new alert: {alert.get('id')} - {alert_time}")
                    analysis = ai_engine.analyze_alert(alert)
                    logger.info(f"AI Analysis Result: {json.dumps(analysis, ensure_ascii=False)}")
                    
                    # Pass to Responder for decision making
                    responder.process_recommendation(analysis, alert)
                    new_alerts_found += 1
                
                if alerts:
                    # Update local state with the latest alert timestamp
                    last_processed_timestamp = alerts[0].get('@timestamp')

                if new_alerts_found == 0:
                    logger.info("No new alerts found.")
                else:
                    logger.info(f"Processed {new_alerts_found} new alerts.")

            logger.info(f"Stepping into sleep mode for {poll_interval}s (Polling Telegram buttons)...")
            start_sleep = time.time()
            while time.time() - start_sleep < poll_interval:
                responder.check_for_telegram_updates()
                time.sleep(2) # Check buttons every 2 seconds
            
    except KeyboardInterrupt:
        logger.info("Real-time monitoring stopped by user.")

if __name__ == "__main__":
    # Ensure logs directory exists
    if not os.path.exists("logs"):
        os.makedirs("logs")
    main()
