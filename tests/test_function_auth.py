import os
import json
from openai import OpenAI


from typing import List, Dict
import sqlite3

class AIAssistantWithTools:
    def __init__(self, db_path="company.db"):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.db = sqlite3.connect(db_path)
        
        # Define available functions
        self.tools = [
            {
                "type": "function",
                "function": {
                    "name": "search_customers",
                    "description": "Search customer database",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"}
                        }
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "update_customer_credit",
                    "description": "Update customer credit limit",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "customer_id": {"type": "integer"},
                            "new_limit": {"type": "number"}
                        }
                    }
                }
            }
        ]
    
    def chat(self, user_message, user_role="customer"):
        """
        HIGH RISK: Function calling without proper authorization checks
        LLM decides which functions to call based on user input
        """
        # Add user role to system prompt, but LLM can ignore this
        system = f"You are a helpful assistant. User role: {user_role}"
        
        response = self.client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_message}
            ],
            tools=self.tools,
            tool_choice="auto"
        )
        
        # VULNERABILITY: No validation that user is authorized for called functions
        # A customer could trick LLM into calling admin functions
        if response.choices[0].message.tool_calls:
            for tool_call in response.choices[0].message.tool_calls:
                function_name = tool_call.function.name
                arguments = json.loads(tool_call.function.arguments)
                
                # CRITICAL: Directly executing function without auth check
                # user_role is ignored - LLM's decision is trusted
                if function_name == "search_customers":
                    result = self.search_customers(**arguments)
                elif function_name == "update_customer_credit":
                    # This should require admin role, but doesn't check!
                    result = self.update_customer_credit(**arguments)
        
        return response.choices[0].message.content
    
    def search_customers(self, query: str):
        """Retrieves customer data - should be role-gated"""
        cursor = self.db.execute(
            f"SELECT * FROM customers WHERE name LIKE '%{query}%'"  # SQL injection too!
        )
        return cursor.fetchall()
    
    def update_customer_credit(self, customer_id: int, new_limit: float):
        """
        CRITICAL: Admin function callable by anyone
        No validation that user has permission
        """
        cursor = self.db.execute(
            f"UPDATE customers SET credit_limit = {new_limit} WHERE id = {customer_id}"
        )
        self.db.commit()
        return f"Updated customer {customer_id}"

