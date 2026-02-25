import json
import os
from openai import OpenAI
from Services.vulnerability_kb import VULNERABILITY_KB

# OpenRouter Configuration — loaded from .env locally, HuggingFace Secrets on prod
OPENROUTER_API_KEY = os.environ["OPENROUTER_API_KEY"]
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=OPENROUTER_API_KEY,
)

def handle_chat_message(message: str, history: list) -> str:
    """
    Handle a user chat message using OpenRouter and KB context.
    """
    # 1. Search KB for relevant info
    kb_context = ""
    message_lower = message.lower()
    
    for key, entry in VULNERABILITY_KB.items():
        if key.replace("_", " ") in message_lower or entry['name'].lower() in message_lower:
            kb_context += f"\n- {entry['name']}: {entry.get('remediation_steps', [{}])[0].get('details', 'Consult documentation.')}"
            if len(kb_context) > 500: # Limit context size
                break

    # 2. Prepare prompt
    system_prompt = f"""
    You are a professional Cyber Security AI Assistant. 
    Provide expert advice based on the provided Knowledge Base and your own training.
    Be concise, technical, and helpful.
    
    Relevant Knowledge Base Context:
    {kb_context if kb_context else "No specific KB entry found for this query."}
    """
    
    messages = [{"role": "system", "content": system_prompt}]
    
    # Add history (last 5 messages)
    for msg in history[-5:]:
        messages.append(msg)
        
    messages.append({"role": "user", "content": message})
    
    try:
        response = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": "https://github.com/antigravity-ai/cyber-ai-dash",
                "X-Title": "Cyber AI Chat",
            },
            model="openai/gpt-4o-mini",
            messages=messages
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        print(f"Chat Service Error: {str(e)}")
        return "I'm sorry, I'm having trouble connecting to my brain right now. Please try again later."
