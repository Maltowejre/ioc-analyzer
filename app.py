import streamlit as st
from utils.validator import detect_ioc_type
from sources.abuseipdb import lookup_ip as abuse_lookup_ip

from sources.otx import (
    lookup_ip as otx_lookup_ip,
    lookup_domain as otx_lookup_domain,
    lookup_hash as otx_lookup_hash,
    lookup_url as otx_lookup_url,
)

from sources.virustotal import (
    lookup_ip as vt_lookup_ip,
    lookup_domain as vt_lookup_domain,
    lookup_hash as vt_lookup_hash,
    lookup_url as vt_lookup_url,
)

from core.scoring import calculate_ip_score, calculate_generic_score, get_verdict


def get_default_otx():
    return {
        "pulse_count": 0,
        "reputation": 0,
        "country_name": "N/A",
        "asn": "N/A",
        "city": "N/A",
    }


def get_default_vt():
    return {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "reputation": 0,
    }

st.set_page_config(page_title="IOC Analyzer", page_icon="🛡️", layout="centered")
st.title("IOC Analyzer")
st.write("Analyze IPs, Domains, URLs, and File Hashes using multiple threat intelligence sources.")
ioc_value = st.text_input("Enter IP / Domain / URL / Hash")

if st.button("Analyze"):
    if not ioc_value.strip():
        st.warning("Please enter an IOC first.")
        st.stop()

    ioc_type = detect_ioc_type(ioc_value.strip())

    if ioc_type == "unknown":
        st.error("Unsupported or invalid IOC.")
        st.stop()

    abuse_result = None
    otx_result = get_default_otx()
    vt_result = get_default_vt()
    
    if ioc_type == "ip":
        abuse_result = abuse_lookup_ip(ioc_value)

        if abuse_result and "error" in abuse_result:
            st.error(f"AbuseIPDB Error: {abuse_result['error']}")
            st.stop()

        tmp_otx = otx_lookup_ip(ioc_value)
        if tmp_otx and "error" not in tmp_otx:
            otx_result = tmp_otx

        tmp_vt = vt_lookup_ip(ioc_value)
        if tmp_vt and "error" not in tmp_vt:
            vt_result = tmp_vt

        threat_score = calculate_ip_score(
            abuse_confidence_score=abuse_result["abuse_confidence_score"],
            otx_pulse_count=otx_result["pulse_count"],
            vt_malicious=vt_result["malicious"],
            vt_suspicious=vt_result["suspicious"],
        )

    elif ioc_type == "domain":
        tmp_otx = otx_lookup_domain(ioc_value)
        if tmp_otx and "error" not in tmp_otx:
            otx_result = tmp_otx

        tmp_vt = vt_lookup_domain(ioc_value)
        if tmp_vt and "error" not in tmp_vt:
            vt_result = tmp_vt

        threat_score = calculate_generic_score(
            otx_pulse_count=otx_result["pulse_count"],
            vt_malicious=vt_result["malicious"],
            vt_suspicious=vt_result["suspicious"],
        )

    elif ioc_type == "hash":
        tmp_otx = otx_lookup_hash(ioc_value)
        if tmp_otx and "error" not in tmp_otx:
            otx_result = tmp_otx

        tmp_vt = vt_lookup_hash(ioc_value)
        if tmp_vt and "error" not in tmp_vt:
            vt_result = tmp_vt

        threat_score = calculate_generic_score(
            otx_pulse_count=otx_result["pulse_count"],
            vt_malicious=vt_result["malicious"],
            vt_suspicious=vt_result["suspicious"],
        )

    elif ioc_type == "url":
        tmp_otx = otx_lookup_url(ioc_value)
        if tmp_otx and "error" not in tmp_otx:
            otx_result = tmp_otx

        tmp_vt = vt_lookup_url(ioc_value)
        if tmp_vt and "error" not in tmp_vt:
            vt_result = tmp_vt

        threat_score = calculate_generic_score(
            otx_pulse_count=otx_result["pulse_count"],
            vt_malicious=vt_result["malicious"],
            vt_suspicious=vt_result["suspicious"],
        )

    else:
        st.error("Unsupported IOC type.")
        st.stop()

    verdict = get_verdict(threat_score)

    st.subheader("Final Analysis")
    col1, col2 = st.columns(2)
    col1.metric("IOC Type", ioc_type.upper())
    col2.metric("Threat Score", threat_score)

    if verdict == "MALICIOUS":
        st.error(f"Verdict: {verdict}")
    elif verdict == "SUSPICIOUS":
        st.warning(f"Verdict: {verdict}")
    else:
        st.success(f"Verdict: {verdict}")

    if abuse_result:
        st.subheader("AbuseIPDB")
        st.write(f"**Abuse Confidence Score:** {abuse_result.get('abuse_confidence_score', 0)}")
        st.write(f"**Total Reports:** {abuse_result.get('total_reports', 0)}")
        st.write(f"**Country Code:** {abuse_result.get('country_code', 'N/A')}")
        st.write(f"**ISP:** {abuse_result.get('isp', 'N/A')}")
        st.write(f"**Domain:** {abuse_result.get('domain', 'N/A')}")
        st.write(f"**Usage Type:** {abuse_result.get('usage_type', 'N/A')}")

    st.subheader("OTX")
    st.write(f"**Pulse Count:** {otx_result.get('pulse_count', 0)}")
    st.write(f"**Reputation:** {otx_result.get('reputation', 0)}")
    st.write(f"**Country:** {otx_result.get('country_name', 'N/A')}")
    st.write(f"**ASN:** {otx_result.get('asn', 'N/A')}")

    st.subheader("VirusTotal")
    st.write(f"**Malicious:** {vt_result.get('malicious', 0)}")
    st.write(f"**Suspicious:** {vt_result.get('suspicious', 0)}")
    st.write(f"**Harmless:** {vt_result.get('harmless', 0)}")
    st.write(f"**Undetected:** {vt_result.get('undetected', 0)}")
    st.write(f"**Reputation:** {vt_result.get('reputation', 0)}")