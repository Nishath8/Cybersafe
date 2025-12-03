import streamlit as st
from typing import Tuple

def render_sidebar() -> Tuple[bool, bool, bool]:
    """
    Renders the sidebar and returns the configuration flags.
    Returns: (run_active_scan, run_advanced_tls, consent_given)
    """
    st.sidebar.title("Cybersafe 🛡️")
    st.sidebar.markdown("Non-intrusive cybersecurity hygiene checker.")
    
    st.sidebar.header("Configuration")
    
    # Toggles
    st.sidebar.subheader("Scan Types")
    passive_checked = st.sidebar.checkbox("Passive Checks (Headers, TLS, CORS)", value=True, disabled=True)
    active_checked = st.sidebar.checkbox("Active Checks (Port Scan)", value=False)
    advanced_tls_checked = st.sidebar.checkbox("Advanced TLS (sslyze)", value=False, help="Requires sslyze to be installed.")
    
    consent_given = False
    
    if active_checked:
        st.sidebar.error("⚠️ Active Scanning Enabled")
        st.sidebar.markdown(
            """
            **Legal & Ethical Notice:**
            Scanning targets you do not own or have explicit permission to test is illegal.
            """
        )
        consent_checkbox = st.sidebar.checkbox("I confirm I own this domain or have explicit permission to scan it.")
        
        if consent_checkbox:
            confirmation_input = st.sidebar.text_input("Type the domain name exactly to confirm:")
            # We can't check the domain here easily because it's in the main area.
            # We will return the confirmation string and check it in main.py
            # Or better, we return the consent boolean only if both are true?
            # The prompt says: "A required checkbox... A typed confirmation... user must re-type the target hostname/domain exactly"
            # So we need the target domain to verify.
            # Let's return the confirmation input string instead of a boolean, or handle it in main.
            
            # Actually, let's just return the checkbox state and the input text, 
            # and let main.py handle the validation against the actual target.
            return active_checked, advanced_tls_checked, (consent_checkbox, confirmation_input)
            
        return active_checked, advanced_tls_checked, (False, "")

    return active_checked, advanced_tls_checked, (True, "") # Consent implicit for passive only? No, active is False.

def render_results(results: dict):
    """Renders the scan results."""
    
    # Score
    score = results.get("score", 0)
    color = "green"
    if score < 50:
        color = "red"
    elif score < 80:
        color = "orange"
        
    st.markdown(f"## Overall Risk Score: :{color}[{score}/100]")
    
    # Tabs for sections
    tabs = st.tabs(["TLS/SSL", "Security Headers", "CORS", "HTTP Methods", "Open Ports"])
    
    with tabs[0]:
        st.subheader("TLS/SSL Configuration")
        if "tls" in results:
            data = results["tls"]
            st.metric("Score", data.get("score", 0))
            if data.get("findings"):
                for f in data["findings"]:
                    st.error(f"**{f['severity']}**: {f['description']}")
                    st.info(f"**Remediation**: {f['remediation']}")
            else:
                st.success("No critical TLS issues found.")
            
            if "details" in data:
                st.json(data["details"])
        else:
            st.info("No TLS data available.")

    with tabs[1]:
        st.subheader("Security Headers")
        if "headers" in results:
            data = results["headers"]
            st.metric("Score", data.get("score", 0))
            if data.get("findings"):
                for f in data["findings"]:
                    st.warning(f"**{f['severity']}**: {f['description']}")
                    st.info(f"**Remediation**: {f['remediation']}")
            else:
                st.success("Security headers look good.")
                
            if "headers" in data:
                with st.expander("View Raw Headers"):
                    st.json(data["headers"])
        else:
            st.info("No headers data available.")

    with tabs[2]:
        st.subheader("CORS Configuration")
        if "cors" in results:
            data = results["cors"]
            st.metric("Score", data.get("score", 0))
            if data.get("findings"):
                for f in data["findings"]:
                    st.error(f"**{f['severity']}**: {f['description']}")
                    st.info(f"**Remediation**: {f['remediation']}")
            else:
                st.success("No CORS issues found.")
            if "details" in data:
                st.json(data["details"])
        else:
            st.info("No CORS data available.")

    with tabs[3]:
        st.subheader("HTTP Methods")
        if "methods" in results:
            data = results["methods"]
            st.metric("Score", data.get("score", 0))
            if data.get("findings"):
                for f in data["findings"]:
                    st.warning(f"**{f['severity']}**: {f['description']}")
                    st.info(f"**Remediation**: {f['remediation']}")
            else:
                st.success("HTTP methods look safe.")
            if "details" in data:
                st.json(data["details"])
        else:
            st.info("No methods data available.")

    with tabs[4]:
        st.subheader("Open Ports (Active Scan)")
        if "ports" in results:
            data = results["ports"]
            st.metric("Score", data.get("score", 0))
            if data.get("findings"):
                for f in data["findings"]:
                    st.error(f"**{f['severity']}**: {f['description']}")
                    st.info(f"**Remediation**: {f['remediation']}")
            else:
                st.success("No open ports found (or scan disabled).")
            if "details" in data:
                st.json(data["details"])
        else:
            st.info("Active scan was not run.")
