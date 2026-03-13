import requests
import logging
import base64
from urllib3.exceptions import InsecureRequestWarning

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class WazuhClient:
    def __init__(self, host, user, password, indexer_host=None, indexer_user=None, indexer_password=None, verify_ssl=False):
        self.host = host.rstrip('/')
        self.user = user
        self.password = password
        self.indexer_host = indexer_host.rstrip('/') if indexer_host else None
        self.indexer_user = indexer_user
        self.indexer_password = indexer_password
        self.verify_ssl = verify_ssl
        self.token = None
        self.logger = logging.getLogger(__name__)

    def get_token(self):
        """
        Authenticates with the Wazuh API and retrieves a JWT token.
        """
        auth_url = f"{self.host}/security/user/authenticate"
        auth_header = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        
        headers = {
            'Authorization': f'Basic {auth_header}',
            'Content-Type': 'application/json'
        }

        try:
            self.logger.info(f"Attempting to authenticate with Wazuh at {self.host}")
            response = requests.post(auth_url, headers=headers, verify=self.verify_ssl, timeout=10)
            
            if response.status_code == 200:
                self.token = response.json().get('data', {}).get('token')
                self.logger.info("Successfully authenticated and retrieved token.")
                return self.token
            else:
                self.logger.error(f"Authentication failed with status code: {response.status_code}")
                self.logger.error(f"Response: {response.text}")
                return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error connecting to Wazuh API: {e}")
            return None

    def get_latest_alerts(self, min_level=7, limit=10, exclude_groups=None):
        """
        Fetches the latest security alerts from Wazuh Indexer.
        """
        if exclude_groups is None:
            exclude_groups = ["sca"] # Default to excluding noisy SCA alerts

        if not self.indexer_host:
            self.logger.error("Indexer host not configured. Cannot fetch alerts.")
            return []

        # Indexer search endpoint
        search_url = f"{self.indexer_host}/wazuh-alerts-*/_search"
        
        # OpenSearch/Elasticsearch query for alerts
        query = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": min_level}}}
                    ],
                    "must_not": [
                        {"terms": {"rule.groups": exclude_groups}}
                    ]
                }
            }
        }

        # Basic Auth for Indexer
        auth = (self.indexer_user, self.indexer_password)
        
        try:
            self.logger.info(f"Fetching alerts from Indexer at {self.indexer_host} (min_level={min_level})...")
            response = requests.post(search_url, json=query, auth=auth, verify=self.verify_ssl, timeout=20)
            
            if response.status_code == 200:
                hits = response.json().get('hits', {}).get('hits', [])
                alerts_data = [hit['_source'] for hit in hits]
                self.logger.info(f"Successfully fetched {len(alerts_data)} alerts from Indexer.")
                return alerts_data
            else:
                self.logger.error(f"Failed to fetch alerts from Indexer. Status code: {response.status_code}")
                self.logger.error(f"Response: {response.text}")
                return []
        except Exception as e:
            self.logger.error(f"Error fetching alerts from Indexer: {e}")
            return []
    def run_active_response(self, agent_id, command, custom_args=None):
        """
        Triggers an Active Response command on a specific agent.
        """
        if not self.token:
            self.get_token()
            
        url = f"{self.host}/active-response?agents_list={agent_id}"
        payload = {
            "command": command,
            "custom_args": custom_args if custom_args else []
        }
        
        headers = {'Authorization': f'Bearer {self.token}', 'Content-Type': 'application/json'}
        
        try:
            self.logger.info(f"Triggering Active Response '{command}' on agent {agent_id}...")
            response = requests.put(url, headers=headers, json=payload, verify=self.verify_ssl, timeout=10)
            if response.status_code == 200:
                self.logger.info(f"Active Response triggered successfully.")
                return True
            else:
                self.logger.error(f"Active Response failed: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            self.logger.error(f"Error triggering Active Response: {e}")
            return False

    def get_alert_by_id(self, alert_id):
        """
        Retrieves a specific alert by its ID from the Indexer.
        """
        if not self.indexer_host: return None
        
        search_url = f"{self.indexer_host}/wazuh-alerts-*/_search"
        query = {
            "query": {
                "match": {
                    "id": alert_id
                }
            }
        }
        auth = (self.indexer_user, self.indexer_password)
        
        try:
            response = requests.post(search_url, json=query, auth=auth, verify=self.verify_ssl, timeout=10)
            if response.status_code == 200:
                hits = response.json().get('hits', {}).get('hits', [])
                if hits:
                    return hits[0]['_source']
            return None
        except Exception as e:
            self.logger.error(f"Error fetching alert by ID: {e}")
            return None
