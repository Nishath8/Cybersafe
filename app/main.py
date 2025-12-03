import streamlit as st
import asyncio
import tldextract
import datetime
from urllib.parse import urlparse
from app.ui import render_sidebar, render_results
from app.scanner.headers_checker import check_headers
from app.scanner.tls_checker import check_tls
from app.scanner.cors_checker import check_cors
from app.scanner.methods_checker import check_methods
from app.scanner.ports_checker import check_ports
from app.utils.caching import ScanCache
from app.utils.scoring import calculate_score
from app.utils.reports import generate_html, generate_pdf
from app.config import DEFAULT_PORTS

# Set page config
st.set_page_config(page_title="Cybersafe", page_icon="🛡️", layout="wide")

async def run_scan(url: str, active: bool, ports: list):
    """Runs the scan asynchronously."""
    
    # Create tasks
    tasks = {
        "headers": asyncio.to_thread(check_headers, url),
        "tls": asyncio.to_thread(check_tls, url),
        "cors": asyncio.to_thread(check_cors, url),
        "methods": asyncio.to_thread(check_methods, url),
    }
    
    if active:
        tasks["ports"] = check_ports(url, ports)
    
    results = {}
    
    # Run tasks and update UI
    # We can't easily update UI from async tasks in Streamlit without some tricks,
    # so we'll just await them all for now or use a placeholder.
    
    # Let's run them concurrently
    results_list = await asyncio.gather(*tasks.values(), return_exceptions=True)
    
    for key, result in zip(tasks.keys(), results_list):
        if isinstance(result, Exception):
            results[key] = {"error": str(result), "score": 0, "findings": []}
        else:
            results[key] = result
            
    return results

def main():
    st.title("Cybersafe 🛡️")
    st.markdown("### Website Security Hygiene Scanner")
    
    # Sidebar
    active_checked, advanced_tls_checked, consent_data = render_sidebar()
    
    # Main Input
    url_input = st.text_input("Enter Domain or URL (e.g., example.com)", "https://example.com")
    
    # Normalize URL
    if not url_input.startswith("http"):
        url_input = f"https://{url_input}"
        
    extracted = tldextract.extract(url_input)
    domain = f"{extracted.domain}.{extracted.suffix}"
    if extracted.subdomain:
        domain = f"{extracted.subdomain}.{domain}"
        
    # Validation for Active Scan
    if active_checked:
        consent_checkbox, confirmation_input = consent_data
        if not consent_checkbox:
            st.warning("⚠️ Active scan selected but consent not checked. Active scan will be skipped.")
        elif confirmation_input != domain:
            st.error(f"⚠️ Domain confirmation mismatch. Typed: '{confirmation_input}', Expected: '{domain}'. Active scan disabled.")
            
    if st.button("Start Scan"):
        # Determine if we can run active scan
        run_active = False
        if active_checked:
            consent_checkbox, confirmation_input = consent_data
            if consent_checkbox and confirmation_input == domain:
                run_active = True
            else:
                st.error("Active scan blocked due to missing consent or mismatch.")
                return

        with st.spinner(f"Scanning {domain}..."):
            # Check cache
            cache = ScanCache()
            cache_key = f"{domain}_{run_active}_{advanced_tls_checked}"
            cached_results = cache.get(cache_key)
            
            if cached_results:
                st.success("Loaded results from cache.")
                results = cached_results
            else:
                # Run Scan
                try:
                    results = asyncio.run(run_scan(url_input, run_active, DEFAULT_PORTS))
                    
                    # Calculate Score
                    results["score"] = calculate_score(results)
                    results["timestamp"] = datetime.datetime.now().isoformat()
                    
                    # Cache results
                    cache.set(cache_key, results)
                    
                except Exception as e:
                    st.error(f"Scan failed: {e}")
                    return
            
            # Render Results
            render_results(results)
            
            # Export
            st.markdown("### Export Report")
            col1, col2, col3 = st.columns(3)
            
            # HTML
            html_report = generate_html(domain, results.get("timestamp"), results.get("score"), results)
            col1.download_button("Download HTML", html_report, file_name=f"cybersafe_report_{domain}.html", mime="text/html")
            
            # PDF
            try:
                pdf_report = generate_pdf(html_report)
                col2.download_button("Download PDF", pdf_report, file_name=f"cybersafe_report_{domain}.pdf", mime="application/pdf")
            except Exception as e:
                col2.error(f"PDF generation failed: {e}")
                
            # JSON
            import json
            col3.download_button("Download JSON", json.dumps(results, indent=2), file_name=f"cybersafe_report_{domain}.json", mime="application/json")

if __name__ == "__main__":
    main()
