import pytest
from unittest.mock import patch, MagicMock
from modules.wazuh_client import WazuhClient

@pytest.fixture
def wazuh_client():
    return WazuhClient(
        host="https://wazuh.manager:55000",
        user="test_user",
        password="test_password",
        indexer_host="https://wazuh.indexer:9200",
        indexer_user="admin",
        indexer_password="admin_password"
    )

@patch('requests.post')
def test_get_token_success(mock_post, wazuh_client):
    # Mock successful response for authentication (Port 55000)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {'data': {'token': 'fake-manager-token'}}
    mock_post.return_value = mock_response

    token = wazuh_client.get_token()
    
    assert token == 'fake-manager-token'
    assert wazuh_client.token == 'fake-manager-token'
    # Verify the call was made to the manager host
    args, kwargs = mock_post.call_args
    assert "https://wazuh.manager:55000" in args[0]

@patch('requests.post')
def test_get_latest_alerts_success(mock_post, wazuh_client):
    # Mock successful response for Indexer search (Port 9200)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        'hits': {
            'hits': [
                {'_source': {'rule': {'level': 10}, '@timestamp': '2023-01-01T00:00:00Z'}}
            ]
        }
    }
    mock_post.return_value = mock_response

    alerts = wazuh_client.get_latest_alerts(min_level=7, limit=5)
    
    assert len(alerts) == 1
    assert alerts[0]['rule']['level'] == 10
    # Verify the call was made to the indexer host
    args, kwargs = mock_post.call_args
    assert "https://wazuh.indexer:9200" in args[0]
    # Check if exclude_groups (sca) is in the query
    assert kwargs['json']['query']['bool']['must_not'][0]['terms']['rule.groups'] == ["sca"]

@patch('requests.post')
def test_get_token_failure(mock_post, wazuh_client):
    # Mock failed response
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.text = "Unauthorized"
    mock_post.return_value = mock_response

    token = wazuh_client.get_token()
    assert token is None
