import json
import os
from openai import OpenAI
from Services.vulnerability_kb import VULNERABILITY_KB, VulnerabilityCategory

# OpenRouter Configuration — loaded from .env locally, HuggingFace Secrets on prod
OPENROUTER_API_KEY = os.environ["OPENROUTER_API_KEY"]
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=OPENROUTER_API_KEY,
)

def analyze_vulnerability(vuln_data: dict) -> dict:
    """
    Analyze vulnerability data using OpenRouter GPT-4.
    Expected input: {'title': str, 'description': str, ...}
    Returns: {
        'risk_score': int (1-10),
        'exploit_likelihood': str (Low, Medium, High, Very High),
        'ai_severity': str (Low, Medium, High, Critical),
        'ai_recommendation': str,
        'remediation_steps': list
    }
    """
    title = vuln_data.get("title", "Unknown Vulnerability")
    description = vuln_data.get("description", "No description provided.")
    
    # Try to find expert context from KB
    kb_entry = None
    search_key = title.lower().replace(" ", "_").replace("-", "_")
    
    if search_key in VULNERABILITY_KB:
        kb_entry = VULNERABILITY_KB[search_key]
    else:
        # Fuzzy search/fallback search
        for key, entry in VULNERABILITY_KB.items():
            if key in search_key or search_key in key or entry['name'].lower() in title.lower():
                kb_entry = entry
                break

    kb_context = ""
    if kb_entry:
        kb_context = f"""
        EXPERT KNOWLEDGE CONTEXT:
        Vulnerability Name: {kb_entry['name']}
        CWE ID: {kb_entry.get('cwe_id', 'N/A')}
        Expert Remediation Action: {kb_entry.get('remediation_steps', [{}])[0].get('action', 'N/A')}
        Indicators: {', '.join(kb_entry.get('indicators', []))}
        """

    prompt = f"""
    You are a cybersecurity expert. Analyze the following vulnerability and return a JSON object.
    
    Vulnerability: {title}
    Description: {description}
    
    {kb_context}
    
    The JSON object MUST contain exactly these keys:
    1. "risk_score": An integer from 1 to 10.
    2. "exploit_likelihood": One of "Low", "Medium", "High", "Very High".
    3. "ai_severity": One of "Low", "Medium", "High", "Critical".
    4. "ai_recommendation": A brief one-sentence summary recommendation.
    5. "remediation_steps": A list of clear, actionable steps.
    
    ONLY return the JSON object, no other text.
    """
    
    try:
        response = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": "https://github.com/antigravity-ai/cyber-ai-dash", # Optional, for including your app on openrouter.ai rankings.
                "X-Title": "Cyber AI Dashboard", # Optional. Shows in rankings on openrouter.ai.
            },
            model="openai/gpt-4o-mini", # Using a fast, cheap model for analysis
            messages=[
                {"role": "system", "content": "You are a professional security researcher."},
                {"role": "user", "content": prompt}
            ]
        )
        
        content = response.choices[0].message.content
        # OpenRouter/GPT sometimes wraps JSON in markdown blocks
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
            
        return json.loads(content)
        
    except Exception as e:
        print(f"AI Analysis Error: {str(e)}")
        # Fallback in case of failure
        return {
            "risk_score": 5,
            "exploit_likelihood": "Medium",
            "ai_severity": "Medium",
            "ai_recommendation": "Manual review required due to AI service error.",
            "remediation_steps": ["Check network logs", "Review system configuration manually"]
        }

def analyze_asset_criticality(asset_data: dict) -> str:
    """
    Analyze asset data using OpenRouter GPT-4 to determine criticality.
    Expected input: {'name': str, 'type': str, 'description': str}
    Returns: "Low", "Medium", "High", or "Critical"
    """
    name = asset_data.get("name", "Unknown Asset")
    asset_type = asset_data.get("type", "Infrastructure")
    description = asset_data.get("description", "No description provided.")
    
    prompt = f"""
    You are a cybersecurity risk assessor. Determine the security criticality of the following asset.
    
    Asset Name: {name}
    Asset Type: {asset_type}
    Description: {description}
    
    Criticality Levels:
    - Critical: Essential infrastructure, if compromised, the entire business stops.
    - High: Production systems containing sensitive data or core services.
    - Medium: Internal tools, development environments, or non-sensitive clusters.
    - Low: Sandbox environments, isolated test machines, or non-functional services.
    
    Respond ONLY with one word: "Low", "Medium", "High", or "Critical".
    """
    
    try:
        response = client.chat.completions.create(
            model="openai/gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a professional security risk assessor."},
                {"role": "user", "content": prompt}
            ]
        )
        
        criticality = response.choices[0].message.content.strip().title()
        if criticality not in ["Low", "Medium", "High", "Critical"]:
            return "Medium"
        return criticality
        
    except Exception as e:
        print(f"AI Criticality Analysis Error: {str(e)}")
        return "Medium"

def analyze_with_gpt(title: str, description: str) -> dict:
    """Compatibility wrapper for old calls if any"""
    return analyze_vulnerability({"title": title, "description": description})