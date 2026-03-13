import unittest
from unittest.mock import MagicMock, patch
from modules.responder import Responder

class TestResponder(unittest.TestCase):
    def setUp(self):
        self.mock_wazuh = MagicMock()
        self.telegram_token = "fake-bot-token"
        self.telegram_chat_id = "12345678"
        self.responder = Responder(self.mock_wazuh, self.telegram_token, self.telegram_chat_id)

    @patch('modules.responder.Responder.isolate_host')
    @patch('modules.responder.audit_logger')
    @patch('modules.responder.Responder.notify_telegram')
    def test_process_recommendation_auto_isolate(self, mock_notify, mock_audit, mock_isolate):
        analysis = {
            "confidence_score": 95,
            "recommended_action": "block",
            "reasoning": "Critical threat"
        }
        alert = {"agent": {"id": "001"}}
        
        self.responder.process_recommendation(analysis, alert)
        
        mock_isolate.assert_called_once_with("001")
        mock_notify.assert_called_once()
        mock_audit.info.assert_called()

    @patch('modules.responder.Responder.notify_telegram')
    @patch('modules.responder.audit_logger')
    def test_process_recommendation_manual_approval(self, mock_audit, mock_notify):
        analysis = {
            "confidence_score": 80,
            "recommended_action": "isolate",
            "reasoning": "Suspicious activity"
        }
        alert = {"agent": {"id": "002"}, "rule": {"description": "Test rule"}}
        
        self.responder.process_recommendation(analysis, alert)
        
        mock_notify.assert_called_once()
        mock_audit.info.assert_called()

    @patch('modules.responder.audit_logger')
    def test_process_recommendation_watch(self, mock_audit):
        analysis = {
            "confidence_score": 50,
            "recommended_action": "watch",
            "reasoning": "Nothing clear"
        }
        alert = {"agent": {"id": "003"}}
        
        self.responder.process_recommendation(analysis, alert)
        
        mock_audit.info.assert_called()

if __name__ == '__main__':
    unittest.main()
