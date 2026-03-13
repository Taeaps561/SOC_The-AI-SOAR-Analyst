import pytest
from unittest.mock import MagicMock, patch
from modules.responder import Responder

@pytest.fixture
def mock_wazuh():
    return MagicMock()

@pytest.fixture
def responder(mock_wazuh):
    return Responder(wazuh_client=mock_wazuh, telegram_token="test_token", telegram_chat_id="test_id")

def test_full_soar_flow_isolation(responder, mock_wazuh):
    """
    Integration Scenario:
    - High Level Alert (Level 10)
    - AI Confidence > 90%
    - Action: isolate
    - Expected Result: Responder calls isolate_host and logs audit.
    """
    
    # 1. Mock Alert Data
    alert_data = {
        "agent": {"id": "001", "name": "web-server"},
        "rule": {"level": 10, "description": "Multiple authentication failures (Brute Force)"},
        "id": "12345.678"
    }

    # 2. Mock AI Analysis Result (Data Type Check: must be JSON/Dict with correct types)
    analysis_result = {
        "confidence_score": 95,            # Integer
        "threat_category": "Brute Force",  # String
        "recommended_action": "isolate",    # String
        "reasoning": "Detected 10+ failed login attempts from a single IP." # String
    }

    # Verify Data Types manually as part of the test
    assert isinstance(analysis_result["confidence_score"], int)
    assert isinstance(analysis_result["threat_category"], str)
    assert isinstance(analysis_result["recommended_action"], str)

    # 3. Process Recommendation
    with patch.object(responder, 'isolate_host', return_value=True) as mock_isolate:
        responder.process_recommendation(analysis_result, alert_data)
        
        # 4. Verify the flow triggered the correct action
        mock_isolate.assert_called_once_with("001")
        
        # Verify logger/audit (optional if we want to check logs)
        # In this case, we just check if the function was called.

def test_full_soar_flow_manual_approval(responder, mock_wazuh):
    """
    Integration Scenario:
    - Medium Level Alert
    - AI Confidence 80% (Between 70-89)
    - Action: block
    - Expected Result: Responder calls notify_telegram.
    """
    
    alert_data = {
        "agent": {"id": "002"},
        "rule": {"level": 5, "description": "Suspicious login"},
    }

    analysis_result = {
        "confidence_score": 80,
        "threat_category": "Suspicious Activity",
        "recommended_action": "block",
        "reasoning": "Login attempt from unusual location."
    }

    with patch.object(responder, 'notify_telegram', return_value=True) as mock_telegram:
        responder.process_recommendation(analysis_result, alert_data)
        
        # 4. Verify Telegram notification was triggered
        mock_telegram.assert_called_once()
