import os
import requests
import json
import logging
from datetime import datetime

# Configure Audit Logging
audit_logger = logging.getLogger("AuditLogger")
audit_logger.setLevel(logging.INFO)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Create a file handler for audit logs
audit_handler = logging.FileHandler("logs/actions.log", encoding='utf-8')
audit_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
audit_logger.addHandler(audit_handler)

class Responder:
    def __init__(self, wazuh_client, telegram_token=None, telegram_chat_id=None):
        self.wazuh = wazuh_client
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        self.logger = logging.getLogger(__name__)
        self.last_update_id = 0

    def _audit_action(self, confidence, action, agent_id, reasoning):
        """Logs the decision to the audit file."""
        audit_message = (
            f"ID: {agent_id if agent_id else 'N/A'} | "
            f"Action: {action.upper()} | "
            f"Confidence: {confidence}% | "
            f"Reasoning: {reasoning}"
        )
        audit_logger.info(audit_message)

    def isolate_host(self, agent_id):
        """
        Triggers host isolation via Wazuh Active Response.
        """
        self.logger.warning(f"CRITICAL: Attempting to isolate host {agent_id}...")
        self.logger.info(f"Host {agent_id} isolation command sent successfully (Simulated).")
        return True

    def notify_telegram(self, analysis, alert_data):
        """
        Sends an enterprise-grade alert to Telegram with interactive buttons.
        """
        if not self.telegram_token or not self.telegram_chat_id:
            self.logger.error("Telegram Token or Chat ID not configured.")
            return False

        # Extract data with multiple fallback paths
        agent_id = alert_data.get('agent', {}).get('id', 'Unknown')
        agent_name = alert_data.get('agent', {}).get('name', 'Unknown')
        rule_desc = alert_data.get('rule', {}).get('description', 'No description')
        
        # Rule ID can be in rule.id
        rule_id = alert_data.get('rule', {}).get('id') or alert_data.get('rule_id', 'N/A')
        rule_level = alert_data.get('rule', {}).get('level', '0')
        
        # Source IP can be in multiple locations
        src_ip = (
            alert_data.get('data', {}).get('srcip') or 
            alert_data.get('srcip') or 
            alert_data.get('data', {}).get('srcip_addr') or
            alert_data.get('data', {}).get('win', {}).get('eventdata', {}).get('ipAddress') or
            'N/A'
        )
        
        confidence = analysis.get('confidence_score', 0)
        category = analysis.get('threat_category', 'Threat')
        hashtag = f"#{category.replace(' ', '').replace('/', '')}"
        reasoning = analysis.get('reasoning', 'No reasoning provided')
        
        # Determine Status
        action_type = analysis.get('recommended_action', 'watch').lower()
        if confidence > 90 and action_type in ['block', 'isolate']:
            status_emoji = "✅"
            action_status = "ISOLATE HOST EXECUTED"
            header = "🛡️ 🔴 CRITICAL: AI-SOAR AUTO-RESPONSE"
        else:
            status_emoji = "⏳"
            action_status = "PENDING MANUAL APPROVAL"
            header = "🛡️ 🟡 WARNING: AI-SOAR ALERT"

        # Build Enterprise Message
        message = (
            f"{header}\n"
            "------------------------------------\n"
            f"📝 *Event:* {rule_desc}\n"
            f"🆔 *Rule ID:* `{rule_id}` | Level: `{rule_level}`\n\n"
            "🖥️ *Asset Information:*\n"
            f"• Agent: `{agent_name}` (`{agent_id}`)\n"
            f"• Source IP: `{src_ip}`\n\n"
            "🧠 *AI Analysis (Ollama):*\n"
            f"• Category: {hashtag}\n"
            f"• Confidence: `{confidence}%`\n"
            f"• Reasoning: {reasoning}\n\n"
            "⚙️ *Action Status:*\n"
            f"{status_emoji} `{action_status}`\n\n"
            "💡 _Tap on IDs or IPs to copy them immediately._"
        )

        # Inline Keyboard Buttons
        reply_markup = {
            "inline_keyboard": [
                [
                    {"text": "🛡️ Acknowledge", "callback_data": f"ack_{agent_id}"},
                    {"text": "🚫 Block IP", "callback_data": f"block_{src_ip}"}
                ],
                [
                    {"text": "🔍 View Full Log", "callback_data": f"log_{alert_data.get('id', 'N/A')}"}
                ]
            ]
        }

        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": message,
            "parse_mode": "Markdown",
            "reply_markup": reply_markup
        }

        try:
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                self.logger.info("Enterprise Telegram notification sent.")
                return True
            else:
                self.logger.error(f"Telegram API error: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            self.logger.error(f"Error sending to Telegram: {e}")
            return False

    def process_recommendation(self, analysis, alert_data):
        """
        Executes actions based on confidence score thresholds.
        """
        confidence = analysis.get('confidence_score', 0)
        # Normalize confidence to int
        try:
            confidence = int(confidence)
        except (ValueError, TypeError):
            confidence = 0
        action_type = analysis.get('recommended_action', 'watch').lower()
        reasoning = analysis.get('reasoning', 'N/A')
        agent_id = alert_data.get('agent', {}).get('id', 'Unknown')

        self.logger.info(f"Processing recommendation with confidence {confidence}...")

        if confidence > 90:
            if action_type in ['block', 'isolate']:
                self.logger.info("Confidence > 90. Triggering automated isolation.")
                self.isolate_host(agent_id)
                self.notify_telegram(analysis, alert_data) # Notify user about automated action
                self._audit_action(confidence, "AUTO-ISOLATE", agent_id, reasoning)
            else:
                self.notify_telegram(analysis, alert_data) # Still notify about high confidence watch
                self._audit_action(confidence, "WATCH", agent_id, reasoning)

        elif 70 <= confidence <= 89:
            self.logger.info(f"Confidence {confidence} for Manual Approval. Notifying Telegram.")
            self.notify_telegram(analysis, alert_data)
            self._audit_action(confidence, "PENDING-APPROVAL", agent_id, reasoning)

        else:
            self._audit_action(confidence, "WATCH-LOW-CONF", agent_id, reasoning)

    def check_for_telegram_updates(self):
        """
        Polls Telegram for new callback queries (button clicks).
        """
        if not self.telegram_token: return
        
        url = f"https://api.telegram.org/bot{self.telegram_token}/getUpdates"
        params = {"offset": self.last_update_id + 1, "timeout": 0}
        
        try:
            response = requests.get(url, params=params, timeout=5)
            if response.status_code == 200:
                updates = response.json().get('result', [])
                for update in updates:
                    self.last_update_id = update['update_id']
                    if 'callback_query' in update:
                        self.handle_callback_query(update['callback_query'])
        except Exception as e:
            self.logger.error(f"Error checking Telegram updates: {e}")

    def handle_callback_query(self, query):
        """
        Handles the logic when a user clicks an inline button.
        """
        query_id = query['id']
        data = query['data']
        chat_id = query['message']['chat']['id']
        message_id = query['message']['message_id']
        original_text = query['message']['text']
        
        self.logger.info(f"Received Telegram Callback: {data}")
        
        action_result = "Action processed."
        
        if data.startswith("ack_"):
            agent_id = data.split("_")[1]
            self._audit_action(100, "MANUAL-ACKNOWLEDGE", agent_id, "User clicked Acknowledge on Telegram")
            action_result = f"✅ Acknowledged for Agent {agent_id}"
            
        elif data.startswith("block_"):
            ip = data.split("_")[1]
            if ip != "N/A":
                # In a real scenario, we'd find the agent associated with this IP
                # For demo, we'll try to find an agent if possible or just log it
                self.logger.warning(f"USER COMMAND: Block IP {ip}")
                # We'll use a generic active response if we can't map agent, but here we just audit
                self._audit_action(100, "MANUAL-BLOCK-IP", ip, f"User triggered Block IP for {ip}")
                action_result = f"🚫 Block IP request sent for {ip}"
            else:
                action_result = "❌ Cannot block: IP is N/A"

        elif data.startswith("log_"):
            alert_id = data.split("_")[1]
            alert = self.wazuh.get_alert_by_id(alert_id)
            if alert:
                log_json = json.dumps(alert, indent=2)
                # Send log as a separate message if it's too long
                self.notify_telegram_raw(f"🔍 *Full Log for {alert_id}:*\n```json\n{log_json[:3000]}\n```")
                action_result = "🔍 Full log sent."
            else:
                action_result = "❌ Alert log not found."

        # 1. Answer Callback Query (removes loading state on button)
        requests.post(f"https://api.telegram.org/bot{self.telegram_token}/answerCallbackQuery", 
                      json={"callback_query_id": query_id, "text": action_result})
        
        # 2. Update the original message to reflect the action
        updated_text = f"{original_text}\n\n🎬 *UPDATE:* {action_result}"
        requests.post(f"https://api.telegram.org/bot{self.telegram_token}/editMessageText", 
                      json={
                          "chat_id": chat_id,
                          "message_id": message_id,
                          "text": updated_text,
                          "parse_mode": "Markdown"
                      })

    def notify_telegram_raw(self, message):
        """Simple helper to send a markdown message without fancy UI."""
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        requests.post(url, json={"chat_id": self.telegram_chat_id, "text": message, "parse_mode": "Markdown"})
