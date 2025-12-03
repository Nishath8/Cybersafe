import httpx
from typing import Dict, Any, List

def check_headers(url: str) -> Dict[str, Any]:
    """
    Checks for the presence and configuration of security headers.
    """
    results = {
        "score": 0,
        "findings": [],
        "headers": {}
    }
    
    try:
        response = httpx.get(url, timeout=10, follow_redirects=True)
        headers = response.headers
        results["headers"] = dict(headers)
        
        # 1. Strict-Transport-Security
        if "Strict-Transport-Security" in headers:
            results["score"] += 10
        else:
            results["findings"].append({
                "severity": "High",
                "description": "Missing Strict-Transport-Security (HSTS) header.",
                "remediation": "Enable HSTS to force HTTPS connections."
            })

        # 2. Content-Security-Policy
        if "Content-Security-Policy" in headers:
            csp = headers["Content-Security-Policy"]
            if "unsafe-inline" in csp or "unsafe-eval" in csp:
                 results["findings"].append({
                    "severity": "Medium",
                    "description": "Content-Security-Policy contains unsafe directives ('unsafe-inline' or 'unsafe-eval').",
                    "remediation": "Refine CSP to avoid using unsafe directives."
                })
                 results["score"] += 5 # Partial credit
            else:
                results["score"] += 10
        else:
            results["findings"].append({
                "severity": "High",
                "description": "Missing Content-Security-Policy (CSP) header.",
                "remediation": "Implement a CSP to mitigate XSS and other attacks."
            })

        # 3. X-Frame-Options
        if "X-Frame-Options" in headers:
            results["score"] += 10
        else:
            results["findings"].append({
                "severity": "Medium",
                "description": "Missing X-Frame-Options header.",
                "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking."
            })

        # 4. X-Content-Type-Options
        if "X-Content-Type-Options" in headers and headers["X-Content-Type-Options"] == "nosniff":
            results["score"] += 10
        else:
             results["findings"].append({
                "severity": "Low",
                "description": "Missing or incorrect X-Content-Type-Options header.",
                "remediation": "Set X-Content-Type-Options to 'nosniff'."
            })
            
        # 5. Referrer-Policy
        if "Referrer-Policy" in headers:
            results["score"] += 5
        else:
             results["findings"].append({
                "severity": "Low",
                "description": "Missing Referrer-Policy header.",
                "remediation": "Set a Referrer-Policy to control information sent in Referer headers."
            })

        # 6. Permissions-Policy
        if "Permissions-Policy" in headers or "Feature-Policy" in headers:
            results["score"] += 5
        else:
             results["findings"].append({
                "severity": "Low",
                "description": "Missing Permissions-Policy (or Feature-Policy) header.",
                "remediation": "Set Permissions-Policy to control browser features."
            })

        # Normalize score to 100 max for this section
        # Max points possible above: 10+10+10+10+5+5 = 50
        # We want to return a raw score that will be weighted later, or a percentage?
        # The prompt says "Deterministic weighted scoring: TLS (30%), headers (30%)..."
        # So let's return a percentage (0-100) for this module.
        
        max_possible = 50
        results["score"] = min(100, int((results["score"] / max_possible) * 100))

    except Exception as e:
        results["error"] = str(e)
        results["score"] = 0
    
    return results
