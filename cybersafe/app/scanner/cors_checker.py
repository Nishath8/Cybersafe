import httpx
from typing import Dict, Any

def check_cors(url: str) -> Dict[str, Any]:
    """
    Checks for insecure CORS configurations.
    """
    results = {
        "score": 100,
        "findings": [],
        "details": {}
    }
    
    # We need to send a request with an Origin header to trigger CORS response
    headers = {"Origin": "https://evil.com"}
    
    try:
        response = httpx.get(url, headers=headers, timeout=10)
        
        acao = response.headers.get("Access-Control-Allow-Origin")
        acac = response.headers.get("Access-Control-Allow-Credentials")
        
        results["details"]["Access-Control-Allow-Origin"] = acao
        results["details"]["Access-Control-Allow-Credentials"] = acac
        
        if acao == "*":
            results["findings"].append({
                "severity": "Medium",
                "description": "Access-Control-Allow-Origin is set to wildcard '*'.",
                "remediation": "Restrict Access-Control-Allow-Origin to trusted domains."
            })
            results["score"] -= 50
            
        if acao == "https://evil.com" and acac == "true":
             results["findings"].append({
                "severity": "High",
                "description": "Server reflects arbitrary Origin with Access-Control-Allow-Credentials: true.",
                "remediation": "Do not reflect the Origin header blindly if credentials are allowed."
            })
             results["score"] = 0
             
        results["score"] = max(0, results["score"])

    except Exception as e:
        results["error"] = str(e)
        results["score"] = 0
        
    return results
