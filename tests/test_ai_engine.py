import unittest
from unittest.mock import patch, MagicMock
from modules.ai_engine import AIEngine
import json

class TestAIEngine(unittest.TestCase):
    def setUp(self):
        self.model = "llama3.2"

    @patch('modules.ai_engine.ollama.Client')
    def test_analyze_alert_success(self, mock_client_class):
        # Setup mock client and response
        mock_client = mock_client_class.return_value
        engine = AIEngine(model=self.model)
        
        expected_json = {
            "confidence_score": 95,
            "threat_category": "Brute Force",
            "recommended_action": "block",
            "reasoning": "Multiple failed logins detected."
        }
        
        # Mock ollama response structure for 'generate'
        mock_response = {
            "response": json.dumps(expected_json)
        }
        mock_client.generate.return_value = mock_response

        alert_data = {"id": "test-alert", "rule": {"level": 10}}
        result = engine.analyze_alert(alert_data)
        
        self.assertEqual(result['confidence_score'], 95)
        self.assertEqual(result['recommended_action'], 'block')

    @patch('modules.ai_engine.ollama.Client')
    def test_analyze_alert_error_fallback(self, mock_client_class):
        # Setup mock client to raise an exception
        mock_client = mock_client_class.return_value
        engine = AIEngine(model=self.model)
        mock_client.generate.side_effect = Exception("Ollama connection error")

        alert_data = {"id": "test-alert"}
        result = engine.analyze_alert(alert_data)
        
        self.assertEqual(result['confidence_score'], 0)
        self.assertEqual(result['recommended_action'], 'watch')
        self.assertIn("Ollama connection error", result['reasoning'])

if __name__ == '__main__':
    unittest.main()
