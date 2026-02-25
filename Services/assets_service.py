import DB
from bson import ObjectId

# CREATE ASSET (Updated with criticality)
def create_asset(asset_data):
    # Set default criticality if not provided
    if "criticality" not in asset_data:
        asset_data["criticality"] = "Medium"  # Default
    result = DB.assets_collection.insert_one(asset_data)
    return str(result.inserted_id)


# GET ASSETS BY OWNER (Updated with criticality)
def get_assets_by_user(user_id):
    assets = list(
        DB.assets_collection.find({"owner_id": ObjectId(user_id)})
    )

    for asset in assets:
        asset["_id"] = str(asset["_id"])
        asset["owner_id"] = str(asset["owner_id"])
        # Ensure criticality field exists for old records
        if "criticality" not in asset:
            asset["criticality"] = "Medium"

    return assets


# GET SINGLE ASSET WITH RISK SCORE (New)
def get_asset_with_risk(asset_id, user_id):
    """Get asset and calculate its overall risk score"""
    asset = DB.assets_collection.find_one({
        "_id": ObjectId(asset_id),
        "owner_id": ObjectId(user_id)
    })
    
    if not asset:
        return None
    
    asset["_id"] = str(asset["_id"])
    asset["owner_id"] = str(asset["owner_id"])
    
    # Get all vulnerabilities for this asset
    vulns = list(DB.vulnerabilities_collection.find({
        "asset_id": ObjectId(asset_id),
        "created_by": ObjectId(user_id),
        "status": "Open"
    }))
    
    # Calculate risk metrics
    if vulns:
        avg_risk = sum(v.get("ai_analysis", {}).get("risk_score", 5) for v in vulns) / len(vulns)
        max_risk = max(v.get("ai_analysis", {}).get("risk_score", 5) for v in vulns)
        critical_count = sum(1 for v in vulns if v.get("ai_analysis", {}).get("ai_severity") == "Critical")
    else:
        avg_risk = 0
        max_risk = 0
        critical_count = 0
    
    asset["risk_metrics"] = {
        "average_risk_score": round(avg_risk, 1),
        "max_risk_score": round(max_risk, 1),
        "open_vulnerabilities": len(vulns),
        "critical_vulnerabilities": critical_count,
        "overall_asset_risk": calculate_asset_risk_level(avg_risk, asset.get("criticality", "Medium"))
    }
    
    return asset


def calculate_asset_risk_level(avg_risk_score, criticality):
    """Determine overall asset risk based on vuln score + asset importance"""
    multipliers = {"Critical": 2.0, "High": 1.5, "Medium": 1.0, "Low": 0.5}
    multiplier = multipliers.get(criticality, 1.0)
    weighted_score = avg_risk_score * multiplier
    
    if weighted_score >= 15:
        return "Critical"
    elif weighted_score >= 10:
        return "High"
    elif weighted_score >= 5:
        return "Medium"
    else:
        return "Low"


# UPDATE ASSET (Updated to allow criticality update)
def update_asset(asset_id, update_data, user_id):
    # Prevent changing owner
    update_data.pop("owner_id", None)
    return DB.assets_collection.update_one(
        {
            "_id": ObjectId(asset_id),
            "owner_id": ObjectId(user_id)
        },
        {"$set": update_data}
    )


# DELETE ASSET
def delete_asset(asset_id, user_id):
    # Also delete associated vulnerabilities
    DB.vulnerabilities_collection.delete_many({
        "asset_id": ObjectId(asset_id),
        "created_by": ObjectId(user_id)
    })
    return DB.assets_collection.delete_one(
        {
            "_id": ObjectId(asset_id),
            "owner_id": ObjectId(user_id)
        }
    )


print("Assets service loaded successfully!")