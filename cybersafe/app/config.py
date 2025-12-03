import os

# Timeouts
HTTP_TIMEOUT = 5.0  # seconds
PORT_SCAN_TIMEOUT = 1.0  # seconds per port

# Ports
DEFAULT_PORTS = [21, 22, 80, 443, 3306, 5432, 6379]

# Caching
CACHE_DIR = os.path.join(os.getcwd(), ".cache")
CACHE_TTL = 43200  # 12 hours in seconds

# Scoring Weights
WEIGHTS = {
    "tls": 30,
    "headers": 30,
    "cors": 15,
    "methods": 15,
    "ports": 10,
}

# User Agent
USER_AGENT = "Cybersafe/1.0 (Security Hygiene Checker; +https://github.com/yourusername/cybersafe)"
