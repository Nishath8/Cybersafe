from typing import Dict, Any
from ..config import WEIGHTS

def calculate_score(results: Dict[str, Any]) -> int:
    """
    Calculates the overall risk score based on individual module scores and weights.
    """
    total_score = 0
    total_weight = 0
    
    # TLS
    if "tls" in results and "score" in results["tls"]:
        total_score += results["tls"]["score"] * WEIGHTS["tls"]
        total_weight += WEIGHTS["tls"]
        
    # Headers
    if "headers" in results and "score" in results["headers"]:
        total_score += results["headers"]["score"] * WEIGHTS["headers"]
        total_weight += WEIGHTS["headers"]
        
    # CORS
    if "cors" in results and "score" in results["cors"]:
        total_score += results["cors"]["score"] * WEIGHTS["cors"]
        total_weight += WEIGHTS["cors"]
        
    # Methods
    if "methods" in results and "score" in results["methods"]:
        total_score += results["methods"]["score"] * WEIGHTS["methods"]
        total_weight += WEIGHTS["methods"]
        
    # Ports (only if active scan was run)
    if "ports" in results and "score" in results["ports"]:
        total_score += results["ports"]["score"] * WEIGHTS["ports"]
        total_weight += WEIGHTS["ports"]
    
    if total_weight == 0:
        return 0
        
    return int(total_score / total_weight)
