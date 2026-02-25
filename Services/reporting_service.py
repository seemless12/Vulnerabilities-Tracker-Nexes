from datetime import datetime, timedelta
from DB import vulnerabilities_collection, assets_collection
from bson import ObjectId
from Services.vulnerability_service import get_top_3_threats as get_top_threats

def generate_executive_report(user_id):
    """Generate C-suite ready executive summary"""
    stats = get_enhanced_dashboard_stats(user_id)
    top_threats = get_top_threats(user_id)
    
    # Calculate risk exposure in dollar terms (example model)
    risk_exposure = calculate_risk_exposure(stats)
    
    # Generate remediation timeline
    timeline = generate_remediation_timeline(user_id)
    
    return {
        "report_generated": datetime.utcnow().isoformat(),
        "executive_summary": {
            "overall_security_posture": assess_posture(stats),
            "critical_findings": len([t for t in top_threats if t["severity"] == "Critical"]),
            "total_risk_exposure_score": stats.get("weighted_risk_score", 0),
            "estimated_financial_impact": f"${risk_exposure:,}" if risk_exposure else "Unknown"
        },
        "key_metrics": {
            "total_assets": stats["total_assets"],
            "vulnerabilities": {
                "total": stats["total_vulnerabilities"],
                "open": stats["open"],
                "critical_open": stats["critical_open"],
                "patched_this_month": stats["patched_this_month"]
            },
            "average_time_to_remediate": f"{stats['avg_resolution_time_hours']:.1f} hours",
            "patch_rate": calculate_patch_rate(stats)
        },
        "top_threats": top_threats,
        "remediation_roadmap": timeline,
        "recommendations": generate_recommendations(stats, top_threats)
    }


def get_enhanced_dashboard_stats(user_id):
    """Enhanced stats for reporting"""
    base_stats = {
        "total_assets": assets_collection.count_documents({"owner_id": ObjectId(user_id)}),
        "total_vulnerabilities": vulnerabilities_collection.count_documents({"created_by": ObjectId(user_id)}),
        "open": vulnerabilities_collection.count_documents({
            "created_by": ObjectId(user_id),
            "status": "Open"
        }),
        "critical_open": vulnerabilities_collection.count_documents({
            "created_by": ObjectId(user_id),
            "status": "Open",
            "ai_analysis.ai_severity": "Critical"
        })
    }
    
    # Calculate weighted risk score
    pipeline = [
        {"$match": {"created_by": ObjectId(user_id), "status": "Open"}},
        {"$group": {
            "_id": None,
            "total_weighted_risk": {
                "$sum": {
                    "$multiply": [
                        "$ai_analysis.risk_score",
                        {"$ifNull": ["$ai_analysis.contextual_priority_score.score", 1]}
                    ]
                }
            }
        }}
    ]
    risk_result = list(vulnerabilities_collection.aggregate(pipeline))
    base_stats["weighted_risk_score"] = round(risk_result[0]["total_weighted_risk"], 1) if risk_result else 0
    
    # Patched this month
    month_ago = datetime.utcnow() - timedelta(days=30)
    base_stats["patched_this_month"] = vulnerabilities_collection.count_documents({
        "created_by": ObjectId(user_id),
        "status": "Patched",
        "patched_at": {"$gte": month_ago}
    })
    
    # Avg resolution time
    res_pipeline = [
        {"$match": {
            "created_by": ObjectId(user_id),
            "status": "Patched",
            "patched_at": {"$exists": True}
        }},
        {"$project": {"hours": {"$divide": [{"$subtract": ["$patched_at", "$created_at"]}, 3600000]}}},
        {"$group": {"_id": None, "avg": {"$avg": "$hours"}}}
    ]
    res_result = list(vulnerabilities_collection.aggregate(res_pipeline))
    base_stats["avg_resolution_time_hours"] = res_result[0]["avg"] if res_result else 0
    
    return base_stats


def calculate_risk_exposure(stats):
    """Estimate financial risk exposure (simplified model)"""
    critical_count = stats.get("critical_open", 0)
    high_count = stats.get("high_open", 0)
    
    # Example: Critical = $100k, High = $50k exposure
    return (critical_count * 100000) + (high_count * 50000)


def assess_posture(stats):
    """Assess overall security posture"""
    critical = stats.get("critical_open", 0)
    if critical > 5:
        return "CRITICAL - Immediate action required"
    elif critical > 0:
        return "HIGH RISK - Address critical issues immediately"
    elif stats.get("open", 0) > 20:
        return "ELEVATED - Significant backlog requires attention"
    else:
        return "MODERATE - Maintain current security practices"


def calculate_patch_rate(stats):
    """Calculate percentage of vulnerabilities patched"""
    total = stats.get("total_vulnerabilities", 0)
    patched = stats.get("total_vulnerabilities", 0) - stats.get("open", 0)
    if total == 0:
        return "100%"
    return f"{(patched/total)*100:.1f}%"


def generate_remediation_timeline(user_id):
    """Generate prioritized remediation plan"""
    timeline = []
    
    # P1: Critical (0-4 hours)
    p1_vulns = list(vulnerabilities_collection.find({
        "created_by": ObjectId(user_id),
        "status": "Open",
        "ai_analysis.contextual_priority_score.priority_level": "P1-Critical"
    }).limit(5))
    
    if p1_vulns:
        timeline.append({
            "phase": "IMMEDIATE (0-4 hours)",
            "items": len(p1_vulns),
            "action": "Address P1 critical vulnerabilities",
            "estimated_effort": f"{len(p1_vulns) * 4} hours"
        })
    
    # P2: High (24 hours)
    p2_count = vulnerabilities_collection.count_documents({
        "created_by": ObjectId(user_id),
        "status": "Open",
        "ai_analysis.contextual_priority_score.priority_level": "P2-High"
    })
    
    if p2_count:
        timeline.append({
            "phase": "SHORT TERM (24 hours)",
            "items": p2_count,
            "action": "Patch P2 high priority issues",
            "estimated_effort": f"{p2_count * 2} hours"
        })
    
    # P3: Medium (7 days)
    p3_count = vulnerabilities_collection.count_documents({
        "created_by": ObjectId(user_id),
        "status": "Open",
        "ai_analysis.contextual_priority_score.priority_level": "P3-Medium"
    })
    
    if p3_count:
        timeline.append({
            "phase": "MEDIUM TERM (7 days)",
            "items": p3_count,
            "action": "Schedule P3 medium priority patches",
            "estimated_effort": f"{p3_count * 1} hours"
        })
    
    return timeline


def generate_recommendations(stats, top_threats):
    """Generate actionable recommendations"""
    recommendations = []
    
    if stats.get("critical_open", 0) > 0:
        recommendations.append({
            "priority": "URGENT",
            "action": "Immediately patch critical vulnerabilities",
            "impact": "Prevents potential system compromise"
        })
    
    if stats.get("avg_resolution_time_hours", 0) > 48:
        recommendations.append({
            "priority": "HIGH",
            "action": "Improve patch management process",
            "impact": "Reduce exposure window from {:.1f} hours to <24 hours".format(
                stats["avg_resolution_time_hours"]
            )
        })
    
    if stats.get("open", 0) > stats.get("patched_this_month", 0) * 2:
        recommendations.append({
            "priority": "MEDIUM",
            "action": "Increase remediation team capacity",
            "impact": "Address backlog of {} open issues".format(stats["open"])
        })
    
    return recommendations


def export_to_pdf(report_data):
    """Placeholder for PDF export functionality"""
    # In production, use libraries like ReportLab or WeasyPrint
    return {
        "status": "PDF generation ready",
        "format": "A4 Executive Report",
        "pages": 5,
        "data": report_data
    }


print("Reporting service loaded successfully!")