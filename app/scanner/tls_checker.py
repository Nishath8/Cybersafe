import ssl
import socket
import datetime
from typing import Dict, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse

def check_tls(url: str) -> Dict[str, Any]:
    """
    Checks TLS certificate validity, expiry, and other properties.
    """
    results = {
        "score": 0,
        "findings": [],
        "details": {}
    }
    
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc
        port = 443
        
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()
                
                results["details"]["cipher"] = cipher
                results["details"]["version"] = version
                
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                
                # Check Expiry
                not_after = cert.not_valid_after
                now = datetime.datetime.utcnow()
                days_left = (not_after - now).days
                
                results["details"]["expiry"] = not_after.isoformat()
                results["details"]["days_left"] = days_left
                
                if days_left < 0:
                    results["findings"].append({
                        "severity": "Critical",
                        "description": f"Certificate expired on {not_after}.",
                        "remediation": "Renew the SSL certificate immediately."
                    })
                    results["score"] = 0 # Fail immediately
                elif days_left < 30:
                    results["findings"].append({
                        "severity": "High",
                        "description": f"Certificate expires soon ({days_left} days).",
                        "remediation": "Renew the SSL certificate."
                    })
                    results["score"] += 50
                else:
                    results["score"] += 100
                
                # Check Issuer (Self-signed detection)
                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()
                results["details"]["issuer"] = issuer
                results["details"]["subject"] = subject
                
                # Simple check for self-signed: issuer == subject (not always perfect but good heuristic for basic check)
                # A better check is if verify_mode failed, but create_default_context verifies by default.
                # If we are here, verification passed (unless we disabled it, which we didn't).
                # So it is likely trusted.
                
                # Check Protocol Version
                if version in ["TLSv1", "TLSv1.1"]:
                     results["findings"].append({
                        "severity": "High",
                        "description": f"Obsolete TLS version detected: {version}.",
                        "remediation": "Disable older TLS versions and support TLS 1.2 or 1.3."
                    })
                     results["score"] = max(0, results["score"] - 50) # Penalize
                
    except ssl.SSLCertVerificationError as e:
        results["findings"].append({
            "severity": "Critical",
            "description": f"Certificate verification failed: {e.verify_message}.",
            "remediation": "Ensure the certificate is valid and issued by a trusted CA."
        })
        results["score"] = 0
    except Exception as e:
        results["error"] = str(e)
        results["score"] = 0

    return results
