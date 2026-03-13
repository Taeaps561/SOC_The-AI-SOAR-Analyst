import os
import json
import logging
import ollama

class AIEngine:
    def __init__(self, api_key=None, model="llama3.2", base_url="http://localhost:11434"):
        """
        Initializes the AIEngine using the native Ollama Python library.
        """
        self.model = model
        self.logger = logging.getLogger(__name__)
        
        # Initialize native Ollama client
        # If the user provides a custom base_url (host), we use it.
        # Note: ollama library uses 'host' instead of 'base_url'
        self.client = ollama.Client(host=base_url) if base_url else ollama
        
        # Define the expert system prompt for local LLM (Enforced JSON)
        self.system_prompt = (
            "You are a Senior SOC Analyst. Analyze the following Wazuh alert and "
            "respond ONLY in valid JSON format. Do not include any conversational text.\n\n"
            "JSON Structure:\n"
            "{\n"
            "  \"confidence_score\": 0-100,\n"
            "  \"threat_category\": \"string\",\n"
            "  \"recommended_action\": \"block\"|\"isolate\"|\"watch\",\n"
            "  \"reasoning\": \"string\"\n"
            "}"
        )

    def analyze_alert(self, alert_data):
        """
        Sends alert data to Llama 3.2 via native Ollama SDK for analysis.
        """
        self.logger.info(f"Sending alert to AI Brain for analysis (Ollama Native: {self.model})...")
        
        # Convert alert data to a readable string format
        alert_json_str = json.dumps(alert_data, indent=2) if isinstance(alert_data, dict) else str(alert_data)
        prompt = f"Wazuh Alert Data: \n{alert_json_str}"

        try:
            # Use ollama.generate (or client.generate)
            response = self.client.generate(
                model=self.model,
                system=self.system_prompt,
                prompt=prompt,
                format="json", # Enforce JSON output at the model level
                options={
                    "temperature": 0.1, # Keep responses deterministic
                    "seed": 42
                }
            )

            # Extract the response text and parse JSON
            analysis_content = response['response']
            analysis_json = json.loads(analysis_content)
            
            self.logger.info("AI Analysis complete.")
            return analysis_json

        except Exception as e:
            self.logger.error(f"Error during native Ollama analysis: {e}")
            # Return a safe fallback response
            return {
                "confidence_score": 0,
                "threat_category": "Error/Unknown",
                "recommended_action": "watch",
                "reasoning": f"Local AI Analysis failed: {str(e)}"
            }
