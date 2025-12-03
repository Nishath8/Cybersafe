import httpx
from typing import Dict, Any

def check_methods(url: str) -> Dict[str, Any]:
    """
    Checks for dangerous HTTP methods enabled.
    """
    results = {
        "score": 100,
        "findings": [],
        "details": {}
    }
    
    try:
        response = httpx.options(url, timeout=10)
        allow_header = response.headers.get("Allow")
        
        if allow_header:
            methods = [m.strip().upper() for m in allow_header.split(",")]
            results["details"]["allowed_methods"] = methods
            
            dangerous_methods = ["TRACE", "TRACK", "PUT", "DELETE", "CONNECT"]
            found_dangerous = [m for m in methods if m in dangerous_methods]
            
            if found_dangerous:
                results["findings"].append({
                    "severity": "Medium",
                    "description": f"Potentially dangerous HTTP methods enabled: {', '.join(found_dangerous)}.",
                    "remediation": "Disable unnecessary HTTP methods like TRACE, TRACK, PUT, DELETE unless required."
                })
                results["score"] -= 20 * len(found_dangerous)
        else:
            results["details"]["message"] = "No Allow header received in OPTIONS response."
            # Not necessarily bad, but we can't verify.
            
        results["score"] = max(0, results["score"])

    except Exception as e:
        results["error"] = str(e)
        results["score"] = 0
        
    return results
