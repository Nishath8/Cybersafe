import pytest
from app.scanner.tls_checker import check_tls
from unittest.mock import patch, MagicMock
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

def generate_self_signed_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"mysite.com")]), critical=False).sign(key, hashes.SHA256(), default_backend())
    return cert.public_bytes(serialization.Encoding.DER)

# We need to mock socket and ssl context because we can't make real connections
@patch("ssl.create_default_context")
@patch("socket.create_connection")
def test_check_tls_mock(mock_create_connection, mock_ssl_context):
    # Setup mocks
    mock_sock = MagicMock()
    mock_create_connection.return_value.__enter__.return_value = mock_sock
    
    mock_ssock = MagicMock()
    mock_context = MagicMock()
    mock_ssl_context.return_value = mock_context
    mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
    
    # Mock cert
    # Generating a real cert is complex, let's just mock the behavior of getpeercert(binary_form=True)
    # and x509.load_der_x509_certificate
    
    # Actually, simpler to mock the x509 load function if we can, or just mock the return of check_tls if we want to test logic around it.
    # But we want to test the logic inside check_tls.
    # Let's mock x509.load_der_x509_certificate
    
    with patch("app.scanner.tls_checker.x509.load_der_x509_certificate") as mock_load:
        mock_cert = MagicMock()
        mock_load.return_value = mock_cert
        
        # Case 1: Valid cert
        mock_cert.not_valid_after = datetime.datetime.utcnow() + datetime.timedelta(days=100)
        mock_cert.issuer.rfc4514_string.return_value = "CN=Trusted CA"
        mock_cert.subject.rfc4514_string.return_value = "CN=mysite.com"
        
        mock_ssock.version.return_value = "TLSv1.3"
        
        results = check_tls("https://mysite.com")
        assert results["score"] == 100
        assert not results["findings"]
        
        # Case 2: Expired cert
        mock_cert.not_valid_after = datetime.datetime.utcnow() - datetime.timedelta(days=1)
        results = check_tls("https://mysite.com")
        assert results["score"] == 0
        assert any("expired" in f["description"] for f in results["findings"])

