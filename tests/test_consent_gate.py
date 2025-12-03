from app.ui import render_sidebar
from unittest.mock import patch

def test_consent_gate():
    # This is tricky to test because it uses Streamlit widgets.
    # We can mock streamlit.sidebar
    with patch("streamlit.sidebar") as mock_sidebar:
        # Case 1: Active checked, consent not checked
        mock_sidebar.checkbox.side_effect = [False, True, False] # Passive (disabled), Active (True), Consent (False)
        
        active, adv, consent = render_sidebar()
        assert active is True
        assert consent[0] is False
        
        # Case 2: Active checked, consent checked, input mismatch
        mock_sidebar.checkbox.side_effect = [False, True, True] # Passive, Active, Consent
        mock_sidebar.text_input.return_value = "wrong.com"
        
        active, adv, consent = render_sidebar()
        assert active is True
        assert consent[0] is True
        assert consent[1] == "wrong.com"
