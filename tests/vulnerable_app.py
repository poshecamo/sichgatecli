"""
Mock AI Application with Security Vulnerabilities
This file intentionally contains security issues for testing SichGate
"""

import os
import logging
from openai import OpenAI

# CRITICAL: Hardcoded API key (should be detected)
OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH"

# Initialize client with hardcoded key
client = OpenAI(api_key=OPENAI_API_KEY)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ChatBot:
    """A vulnerable chatbot implementation"""
    
    def __init__(self):
        self.system_prompt = "You are a helpful assistant."
    
    def chat(self, user_message, user_email=None, user_phone=None):
        """
        HIGH RISK: Direct string concatenation with user input
        Vulnerable to prompt injection
        """
        # Dangerous: user input directly in prompt without validation
        full_prompt = f"System: {self.system_prompt}\nUser: {user_message}\nAssistant:"
        
        # MEDIUM RISK: Logging PII
        logger.info(f"User query from {user_email}: {user_message}")
        if user_phone:
            print(f"Contact: {user_phone}")
        
        # Make API call (this would fail without real key, but code is vulnerable)
        try:
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": user_message}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"API Error: {e}")
            return "Error processing request"
    
    def generate_code(self, user_requirements):
        """
        HIGH RISK: No input validation before sending to LLM
        Could generate malicious code
        """
        # No validation or sanitization
        prompt = "Generate code for: " + user_requirements
        
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        
        generated_code = response.choices[0].message.content
        
        # CRITICAL: Logging generated code (could contain secrets)
        logger.info(f"Generated code: {generated_code}")
        
        return generated_code


def process_user_input(user_text):
    """
    MEDIUM RISK: No input validation
    Accepts any user input without sanitization
    """
    # No validation, cleaning, or filtering
    bot = ChatBot()
    return bot.chat(user_text)


def admin_function(password, ssn, credit_card):
    """
    MEDIUM RISK: PII in function parameters
    These could be logged or exposed
    """
    logger.info(f"Admin login attempt with password: {password}")
    print(f"Processing SSN: {ssn}, Card: {credit_card}")
    
    if password == "admin123":  # Weak hardcoded password
        return "Access granted"
    return "Access denied"


# Example usage showing vulnerable patterns
if __name__ == "__main__":
    bot = ChatBot()
    
    # This input could be a prompt injection attack
    user_input = input("Enter your message: ")
    
    # No validation before processing
    response = bot.chat(
        user_input, 
        user_email="user@example.com",
        user_phone="555-1234"
    )
    
    print(response)
    
    # Another vulnerable pattern: .format() with user data
    query = "Tell me about {}".format(user_input)
    
    # Yet another: string concatenation
    final_query = "User asked: " + user_input + " - please respond"