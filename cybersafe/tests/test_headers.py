import pytest
from app.scanner.headers_checker import check_headers
import respx
from httpx import Response

@respx.mock
def test_check_headers_secure():
    respx.get("https://secure.com").mock(return_value=Response(200, headers={
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()"
    }))
    
    results = check_headers("https://secure.com")
    assert results["score"] == 100
    assert not results["findings"]

@respx.mock
def test_check_headers_insecure():
    respx.get("https://insecure.com").mock(return_value=Response(200, headers={}))
    
    results = check_headers("https://insecure.com")
    assert results["score"] == 0
    assert len(results["findings"]) >= 5

@respx.mock
def test_check_headers_unsafe_csp():
    respx.get("https://unsafe.com").mock(return_value=Response(200, headers={
        "Content-Security-Policy": "script-src 'unsafe-inline'"
    }))
    
    results = check_headers("https://unsafe.com")
    # Should have findings about unsafe-inline
    assert any("unsafe-inline" in f["description"] for f in results["findings"])
