import os
import json
import subprocess
from openai import OpenAI


import json
import subprocess

class CodeReviewAgent:
    def __init__(self):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    
    def review_code(self, code_snippet, user_id):
        """
        CRITICAL ISSUE: Using LLM to make security decisions
        LLM can be manipulated to approve malicious code
        """
        prompt = f"""Analyze this code for security issues. 
        Respond with JSON: {{"safe": true/false, "issues": []}}
        
        Code to review:
        {code_snippet}
        """
        
        response = self.client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        
        # VULNERABILITY: Trusting LLM's security assessment without validation
        # LLM could be manipulated via prompt injection in the code itself
        analysis = json.loads(response.choices[0].message.content)
        
        if analysis["safe"]:
            # CRITICAL: Executing code based on LLM approval
            self.execute_user_code(code_snippet, user_id)
        
        return analysis
    
    def execute_user_code(self, code, user_id):
        """
        CRITICAL: Actually executing code that LLM deemed "safe"
        """
        # Write to temp file and execute
        with open(f"/tmp/user_{user_id}_code.py", "w") as f:
            f.write(code)
        
        # Execute without sandboxing
        result = subprocess.run(
            ["python", f"/tmp/user_{user_id}_code.py"],
            capture_output=True,
            timeout=5
        )
        return result.stdout
