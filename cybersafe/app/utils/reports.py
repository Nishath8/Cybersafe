import jinja2
from typing import Dict, Any
import json
import os
import logging

# Try to import WeasyPrint, handle missing GTK on Windows
try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except OSError:
    WEASYPRINT_AVAILABLE = False
    logging.warning("WeasyPrint could not be loaded (likely missing GTK). PDF export disabled.")
except ImportError:
    WEASYPRINT_AVAILABLE = False
    logging.warning("WeasyPrint not installed. PDF export disabled.")

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Cybersafe Security Report</title>
    <style>
        body { font-family: sans-serif; }
        h1, h2, h3 { color: #333; }
        .score { font-size: 2em; font-weight: bold; }
        .high { color: red; }
        .medium { color: orange; }
        .low { color: blue; }
        .good { color: green; }
        .finding { border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; }
        .severity { font-weight: bold; }
    </style>
</head>
<body>
    <h1>Cybersafe Security Report</h1>
    <p>Target: {{ target }}</p>
    <p>Date: {{ date }}</p>
    
    <h2>Overall Score: <span class="score {{ score_class }}">{{ score }}</span></h2>
    
    {% for module, data in results.items() %}
    {% if data.findings %}
    <h3>{{ module|upper }} Findings</h3>
    {% for finding in data.findings %}
    <div class="finding">
        <p><span class="severity {{ finding.severity|lower }}">{{ finding.severity }}</span>: {{ finding.description }}</p>
        <p><strong>Remediation:</strong> {{ finding.remediation }}</p>
    </div>
    {% endfor %}
    {% endif %}
    {% endfor %}
    
    <h3>Raw Data</h3>
    <pre>{{ raw_data }}</pre>
</body>
</html>
"""

def generate_html(target: str, date: str, score: int, results: Dict[str, Any]) -> str:
    """Generates an HTML report."""
    score_class = "good"
    if score < 50:
        score_class = "high"
    elif score < 80:
        score_class = "medium"
        
    template = jinja2.Template(TEMPLATE)
    return template.render(
        target=target,
        date=date,
        score=score,
        score_class=score_class,
        results=results,
        raw_data=json.dumps(results, indent=2)
    )

def generate_pdf(html_content: str) -> bytes:
    """Generates a PDF from HTML content."""
    if not WEASYPRINT_AVAILABLE:
        raise RuntimeError("PDF generation unavailable (missing GTK libraries).")
    return HTML(string=html_content).write_pdf()
