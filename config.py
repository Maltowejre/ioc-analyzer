import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

try:
    import streamlit as st

    if "VT_API_KEY" in st.secrets:
        VT_API_KEY = st.secrets["VT_API_KEY"]

    if "ABUSEIPDB_API_KEY" in st.secrets:
        ABUSEIPDB_API_KEY = st.secrets["ABUSEIPDB_API_KEY"]

    if "OTX_API_KEY" in st.secrets:
        OTX_API_KEY = st.secrets["OTX_API_KEY"]

except Exception:
    pass