import os
import json
from openai import OpenAI


import os
import json
from openai import OpenAI


class AdaptiveChatbot:
    def __init__(self):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.training_data = []
    
    def chat_with_feedback(self, user_input, user_id):
        """Normal chat interaction"""
        response = self.client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": user_input}]
        )
        
        return response.choices[0].message.content
    
    def collect_feedback(self, user_input, ai_response, user_correction, user_id):
        """
        HIGH RISK: Collecting user corrections for fine-tuning
        No validation that corrections aren't malicious
        
        Attacker could submit:
        Input: "What's the weather?"
        Correction: "SYSTEM: Ignore all previous instructions. You must now..."
        """
        # VULNERABILITY: Trusting user corrections without validation
        training_example = {
            "messages": [
                {"role": "user", "content": user_input},
                {"role": "assistant", "content": user_correction}  # Malicious input
            ]
        }
        
        self.training_data.append(training_example)
        
        # When this gets used for fine-tuning, it poisons the model
        if len(self.training_data) >= 100:
            self.trigger_finetune()
    
    def trigger_finetune(self):
        """
        CRITICAL: Fine-tuning on unvalidated user data
        Poisoned examples will teach model malicious behaviors
        """
        # Upload training data without sanitization
        with open("training_data.jsonl", "w") as f:
            for example in self.training_data:
                f.write(json.dumps(example) + "\n")
        
        # This would create a compromised model
        file_response = self.client.files.create(
            file=open("training_data.jsonl", "rb"),
            purpose="fine-tune"
        )