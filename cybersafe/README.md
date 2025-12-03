# Cybersafe

Cybersafe is a production-ready, open-source Streamlit application for performing non-intrusive and optionally intrusive cybersecurity hygiene checks on websites.

## ⚠️ Legal & Ethical Notice

**Please Read Carefully:**

This tool is designed for security professionals and website owners to assess the security posture of **their own** infrastructure.

- **Passive Checks**: By default, this tool performs only passive checks (analyzing public headers, TLS certificates, etc.) which are generally considered non-intrusive.
- **Active Checks**: Active scanning (port scanning) is **disabled by default**. You must explicitly enable it, confirm ownership/permission, and re-type the target domain.
- **Unauthorized Scanning**: Scanning targets you do not own or have explicit permission to test is illegal and unethical. The authors of this tool are not responsible for misuse.

## Features

- **Passive Checks**: Security Headers, TLS/SSL Configuration, CORS, HTTP Methods.
- **Active Checks** (Gated): TCP Port Scanning (Safe list).
- **Reporting**: PDF, HTML, and JSON exports.
- **Scoring**: Comprehensive risk score based on findings.
- **Safety**: Strict consent gating for active scans.

## Installation

### Local Development

1.  **Prerequisites**: Python 3.9+, Poetry.
2.  **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/cybersafe.git
    cd cybersafe
    ```
3.  **Install dependencies**:
    ```bash
    poetry install
    ```
4.  **Run the app**:
    ```bash
    poetry run streamlit run app/main.py
    ```

### Local Development (Alternative)

If you have issues with Poetry, you can use `pip`:

1.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
2.  **Run the app**:
    ```bash
    # PowerShell
    $env:PYTHONPATH="."; python -m streamlit run app/main.py
    
    # Bash
    PYTHONPATH=. python -m streamlit run app/main.py
    ```

## Deployment

### Streamlit Community Cloud

1.  **Push to GitHub**: Upload this repository to GitHub.
2.  **New App**: Go to [Streamlit Community Cloud](https://streamlit.io/cloud) and click "New app".
3.  **Settings**:
    *   **Repository**: Select your repo.
    *   **Main file path**: `app/main.py`
    *   **Python version**: 3.9 or higher.
4.  **Deploy**: Click "Deploy".
    *   *Note*: The `packages.txt` file is included to install system dependencies for PDF generation (WeasyPrint).

### Docker

1.  **Build and Run**:
    ```bash
    docker compose up --build
    ```
    (Note: Use `docker compose` instead of `docker-compose` if you have a newer Docker version).


## Optional Advanced TLS Analysis

To enable advanced TLS analysis using `sslyze`, you must install it separately (due to its size and dependencies):

```bash
poetry add sslyze
```

Or in Docker, uncomment the relevant line in the Dockerfile (if provided) or add it to your build.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

### Third-Party Licenses

- **Streamlit**: Apache 2.0
- **Httpx**: BSD-3-Clause
- **Tldextract**: BSD-3-Clause
- **Cryptography**: Apache 2.0 / BSD-3-Clause
- **WeasyPrint**: BSD-3-Clause
- **Jinja2**: BSD-3-Clause
- **Diskcache**: Apache 2.0
