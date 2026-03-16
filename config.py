import os
from dotenv import load_dotenv
load_dotenv()
try:
    import streamlit as st

    VT_API_KEY = st.secrets.get("VT_API_KEY", os.getenv("VT_API_KEY"))
    ABUSEIPDB_API_KEY = st.secrets.get("ABUSEIPDB_API_KEY", os.getenv("ABUSEIPDB_API_KEY"))
    OTX_API_KEY = st.secrets.get("OTX_API_KEY", os.getenv("OTX_API_KEY"))

except Exception:
    VT_API_KEY = os.getenv("VT_API_KEY")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    OTX_API_KEY = os.getenv("OTX_API_KEY")