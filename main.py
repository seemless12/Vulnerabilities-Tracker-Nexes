from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv
load_dotenv()  # loads .env for local dev; HuggingFace uses its own env vars
from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId
from typing import Optional, List
from Services.User_service import create_user, authenticate_user
from Services.assets_service import (
    create_asset, 
    get_assets_by_user, 
    update_asset, 
    delete_asset,
    get_asset_with_risk
)
from Services.vulnerability_service import (
    create_vulnerability, 
    get_vulnerabilities_by_asset,
    get_prioritized_vulnerabilities,
    update_vulnerability_status,
    get_dashboard_stats,
    delete_vulnerability,
    get_top_3_threats
)
from Services.reporting_service import generate_executive_report, export_to_pdf
from Services.ai_service import analyze_vulnerability, analyze_asset_criticality
from Services.chat_service import handle_chat_message
from Services.vulnerability_kb import VULNERABILITY_KB, VulnerabilityCategory
from auth import create_access_token, get_current_user
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime
import os

app = FastAPI(title="AI Vulnerability Intelligence Dashboard")

# CORS — allow frontend to call API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Pydantic Models ───────────────────────────────────────────

class UserRegister(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class AssetCreate(BaseModel):
    name: str
    type: str # Missing input from frontend previously, now required
    description: Optional[str] = "No description provided"

class AssetUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    description: Optional[str] = None
    criticality: Optional[str] = None

class VulnerabilityCreate(BaseModel):
    asset_id: str
    title: str
    description: str
    cve_id: Optional[str] = None

class VulnerabilityStatusUpdate(BaseModel):
    status: str  # Open, In Progress, Patched, False Positive
    resolution_note: Optional[str] = None

class ChatMessage(BaseModel):
    message: str
    history: Optional[List[dict]] = []

class KBEntry(BaseModel):
    key: str
    name: str
    severity: str
    category: str


# ─── Auth Endpoints ────────────────────────────────────────────

@app.post("/users/")
def register_user(user: UserRegister):
    """Register a new user"""
    from DB import users_collection
    existing = users_collection.find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = create_user(user.dict())
    return {"id": user_id, "message": "User registered successfully"}


@app.post("/login")
def login(user: UserLogin):
    """Login and receive JWT token"""
    db_user = authenticate_user(user.email, user.password)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"user_id": str(db_user["_id"])})
    return {
        "access_token": token,
        "token_type": "bearer",
        "name": db_user.get("name", "User")
    }

# ASSETS ENDPOINTS

@app.post("/assets/")
def add_asset(
    asset_data: AssetCreate,
    user_id: str = Depends(get_current_user)
):
    data = asset_data.dict()
    data["owner_id"] = ObjectId(user_id)
    data["created_at"] = datetime.utcnow()
    
    # AI identifies criticality based on name, type, and description
    data["criticality"] = analyze_asset_criticality(data)
    
    asset_id = create_asset(data)
    return {
        "id": asset_id, 
        "message": "Asset created successfully", 
        "criticality": data["criticality"]
    }


@app.get("/assets/")
def get_my_assets(user_id: str = Depends(get_current_user)):
    return get_assets_by_user(user_id)


@app.get("/assets/{asset_id}")
def get_asset_detail(
    asset_id: str,
    user_id: str = Depends(get_current_user)
):
    """Get asset with risk metrics"""
    asset = get_asset_with_risk(asset_id, user_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    return asset


@app.put("/assets/{asset_id}")
def update_asset_endpoint(
    asset_id: str,
    update_data: AssetUpdate,
    user_id: str = Depends(get_current_user)
):
    result = update_asset(asset_id, update_data.dict(exclude_unset=True), user_id)
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Asset not found or no changes")
    
    return {"message": "Asset updated successfully"}


@app.delete("/assets/{asset_id}")
def delete_asset_endpoint(
    asset_id: str,
    user_id: str = Depends(get_current_user)
):
    result = delete_asset(asset_id, user_id)
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    return {"message": "Asset and associated vulnerabilities deleted"}


# VULNERABILITY ENDPOINTS

@app.post("/vulnerabilities/analyze")
def analyze_vuln_preview(data: dict):
    """Preview AI analysis without saving"""
    analysis = analyze_vulnerability(data)
    return analysis


@app.post("/vulnerabilities/")
def add_vulnerability(
    vuln_data: VulnerabilityCreate,
    user_id: str = Depends(get_current_user)
):
    data = vuln_data.dict()
    data["created_by"] = user_id
    
    vulnerability_id = create_vulnerability(data)
    return {
        "id": vulnerability_id,
        "message": "Vulnerability created with AI analysis"
    }


@app.get("/vulnerabilities/prioritized")
def get_prioritized_list(
    severity: Optional[str] = Query(None, description="Filter by severity: Critical, High, Medium, Low"),
    user_id: str = Depends(get_current_user)
):
    """Get all vulnerabilities sorted by AI contextual priority"""
    return get_prioritized_vulnerabilities(user_id, severity_filter=severity)


@app.get("/assets/{asset_id}/vulnerabilities")
def get_asset_vulns(
    asset_id: str,
    user_id: str = Depends(get_current_user)
):
    return get_vulnerabilities_by_asset(asset_id, user_id)


@app.patch("/vulnerabilities/{vuln_id}/status")
def update_vuln_status(
    vuln_id: str,
    update_data: VulnerabilityStatusUpdate,
    user_id: str = Depends(get_current_user)
):
    result = update_vulnerability_status(
        vuln_id,
        update_data.status,
        update_data.resolution_note,
        user_id
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    return {"message": f"Status updated to {update_data.status}"}


@app.delete("/vulnerabilities/{vuln_id}")
def delete_vuln(
    vuln_id: str,
    user_id: str = Depends(get_current_user)
):
    result = delete_vulnerability(vuln_id, user_id)
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    return {"message": "Vulnerability deleted"}


# DASHBOARD & REPORTING ENDPOINTS

@app.get("/dashboard/stats")
def get_stats(user_id: str = Depends(get_current_user)):
    """Get vulnerability statistics for dashboard"""
    return get_dashboard_stats(user_id)


@app.get("/dashboard/critical-now")
def get_critical_now(user_id: str = Depends(get_current_user)):
    """Get critical vulnerabilities requiring immediate action"""
    critical_vulns = list(get_prioritized_vulnerabilities(user_id))
    return [v for v in critical_vulns if v.get("ai_analysis", {}).get("ai_severity") == "Critical"][:10]


@app.get("/reports/executive-summary")
def executive_report(user_id: str = Depends(get_current_user)):
    """Generate C-suite executive summary"""
    return generate_executive_report(user_id)


@app.post("/reports/export")
def export_report(
    format: str = Query("json", enum=["json", "pdf"]),
    user_id: str = Depends(get_current_user)
):
    """Export report in specified format"""
    report = generate_executive_report(user_id)
    
    if format == "pdf":
        return export_to_pdf(report)
    
    return report


# ─── New KB & Chat Endpoints ────────────────────────────────────

@app.post("/chat")
def chat_endpoint(
    chat_data: ChatMessage,
    user_id: str = Depends(get_current_user)
):
    """Handle chat conversations with AI"""
    response = handle_chat_message(chat_data.message, chat_data.history)
    return {"reply": response}


@app.get("/kb")
def get_kb_list(
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None)
):
    """List all vulnerabilities in the knowledge base"""
    results = []
    for key, entry in VULNERABILITY_KB.items():
        if category and entry.get("category") != category:
            continue
        if severity and entry.get("severity") != severity:
            continue
            
        results.append({
            "id": key,
            "name": entry["name"],
            "severity": entry["severity"],
            "category": entry["category"],
            "cwe_id": entry.get("cwe_id", "N/A"),
            "owasp_rank": entry.get("owasp_rank", "N/A")
        })
    return results


@app.get("/kb/{kb_id}")
def get_kb_detail(kb_id: str):
    """Get detailed information about a KB entry"""
    if kb_id not in VULNERABILITY_KB:
        raise HTTPException(status_code=404, detail="KB Entry not found")
    
    entry = VULNERABILITY_KB[kb_id]
    # Convert enum values to strings for JSON serialization if necessary
    # VulnerabilityCategory and SeverityLevel seem to be string enums based on the outline
    return entry


# ─── Serve Frontend ────────────────────────────────────────────
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")

@app.get("/")
def serve_index():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

app.mount("/", StaticFiles(directory=FRONTEND_DIR), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
