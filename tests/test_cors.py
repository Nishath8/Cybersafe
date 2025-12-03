import pytest
from app.scanner.cors_checker import check_cors
import respx
from httpx import Response

@respx.mock
def test_check_cors_secure():
    respx.get("https://secure.com").mock(return_value=Response(200, headers={
        "Access-Control-Allow-Origin": "https://trusted.com"
    }))
    
    results = check_cors("https://secure.com")
    assert results["score"] == 100

@respx.mock
def test_check_cors_wildcard():
    respx.get("https://insecure.com").mock(return_value=Response(200, headers={
        "Access-Control-Allow-Origin": "*"
    }))
    
    results = check_cors("https://insecure.com")
    assert results["score"] <= 50
    assert any("wildcard" in f["description"] for f in results["findings"])
