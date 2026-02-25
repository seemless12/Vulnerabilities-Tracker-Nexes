# 🛡️ Nexes - AI Vulnerability Intelligence Dashboard

<p align="center">
  <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white" />
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/OpenAI-412991?style=for-the-badge&logo=openai&logoColor=white" />
  <img src="https://img.shields.io/badge/Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white" />
</p>

<p align="center">
  <b>AI-Powered Cybersecurity Asset & Vulnerability Management Platform</b>
</p>

---

## 🎯 What is Nexes?

Nexes is an intelligent security management platform that helps organizations track digital assets, analyze vulnerabilities, and prioritize remediation using artificial intelligence. It transforms raw security scan data into actionable intelligence, enabling security teams to fix what matters most first.

### 🏥 The Problem We Solve

Organizations face thousands of vulnerabilities across their infrastructure:
- **500+ vulnerabilities** found in average security scan
- **No clear prioritization** - which one is actually exploitable?
- **Wasted resources** fixing low-risk issues while critical ones remain open
- **No visibility** for leadership on security posture

### 💡 Our Solution

Nexes acts as your **AI Security Analyst**:
- 🔍 **Auto-classifies** vulnerability severity using AI
- 🧠 **Calculates contextual risk** based on asset importance  
- 📊 **Prioritizes remediation** by actual business impact
- 📈 **Generates executive reports** for C-suite visibility

---

## ✨ Key Features

### 🔐 Core Security
| Feature | Description |
|---------|-------------|
| **JWT Authentication** | Secure, stateless user sessions |
| **Role-Based Access** | Users only see their own assets |
| **Password Hashing** | bcrypt with salt for credential protection |

### 🖥️ Asset Management
- Register servers, APIs, databases, cloud instances
- Assign criticality levels (Critical/High/Medium/Low)
- Track asset-vulnerability relationships
- Risk scoring per asset based on open vulnerabilities

### 🤖 AI-Powered Vulnerability Analysis
- **Automatic Severity Classification** (Critical/High/Medium/Low)
- **Risk Score Calculation** (1-10 scale)
- **Contextual Prioritization** (vuln risk × asset criticality)
- **Step-by-Step Remediation** with code examples
- **Exploit Scenario Generation**
- **Compliance Impact Assessment** (GDPR, HIPAA, PCI-DSS)

### 📊 Intelligence & Reporting
- **Executive Dashboard** - C-suite ready security summaries
- **Prioritized Remediation Queue** - Fix order by actual risk
- **Financial Risk Estimation** - Quantify exposure in dollars
- **Trend Analysis** - Track security posture over time
- **PDF Report Export** - Compliance documentation

### 📚 Knowledge Base
Built-in encyclopedia of 20+ vulnerability types:
- SQL Injection, XSS, CSRF, SSRF
- Broken Authentication, Access Control
- Cryptographic Failures
- Security Misconfiguration
- Each with detailed remediation steps

---

## 🏗️ Architecture
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   React/Vue     │────→│   FastAPI        │────→│   MongoDB       │
│   Frontend      │     │   Python API     │     │   Database      │
│   (Optional)    │     │                  │     │                 │
└─────────────────┘     └──────────────────┘     └─────────────────┘
│
↓
┌──────────────────┐
│   AI Engine      │
│   - GPT-4/Claude │
│   - Rule-based   │
│   - Risk Scoring │
└──────────────────┘
plain
Copy

---

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- MongoDB Atlas account (or local MongoDB)
- (Optional) OpenAI API key for advanced AI features

### Local Installation

```bash
# 1. Clone repository
git clone https://github.com/yourusername/nexes.git
cd nexes

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set environment variables
export MONGODB_URI="your-mongodb-connection-string"
export SECRET_KEY="your-secret-key-for-jwt"

# 5. Run development server
uvicorn main:app --reload

# 6. Open API docs
open http://localhost:8000/docs
Deploy to Vercel (Production)
bash
Copy
# 1. Install Vercel CLI
npm i -g vercel

# 2. Login and deploy
vercel login
vercel --prod
