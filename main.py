import sys
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
from core.analyzer import save_result
from utils.formatter import print_analysis_result

def get_default_otx():
    return {
        "source": "OTX",
        "pulse_count": 0,
        "reputation": 0,
        "country_name": "N/A",
        "asn": "N/A",
        "city": "N/A",
    }

def get_default_vt():
    return {
        "source": "VirusTotal",
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "reputation": 0,
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <IOC>")
        return

    ioc_value = sys.argv[1]
    ioc_type = detect_ioc_type(ioc_value)

    if ioc_type == "unknown":
        print("Error: Unsupported or invalid IOC")
        return

    abuse_result = None
    otx_result = get_default_otx()
    vt_result = get_default_vt()

    if ioc_type == "ip":
        abuse_result = abuse_lookup_ip(ioc_value)
        if "error" in abuse_result:
            print("\nAbuseIPDB Error:")
            print(abuse_result["error"])
            return

        tmp_otx = otx_lookup_ip(ioc_value)
        if "error" not in tmp_otx:
            otx_result = tmp_otx

        tmp_vt = vt_lookup_ip(ioc_value)
        if "error" not in tmp_vt:
            vt_result = tmp_vt

        threat_score = calculate_ip_score(
            abuse_confidence_score=abuse_result["abuse_confidence_score"],
            otx_pulse_count=otx_result["pulse_count"],
            vt_malicious=vt_result["malicious"],
            vt_suspicious=vt_result["suspicious"],
        )

    elif ioc_type == "domain":
        tmp_otx = otx_lookup_domain(ioc_value)
        if "error" not in tmp_otx:
            otx_result = tmp_otx

        tmp_vt = vt_lookup_domain(ioc_value)
        if "error" not in tmp_vt:
            vt_result = tmp_vt

        threat_score = calculate_generic_score(
            otx_pulse_count=otx_result["pulse_count"],
            vt_malicious=vt_result["malicious"],
            vt_suspicious=vt_result["suspicious"],
        )

    elif ioc_type == "hash":
        tmp_otx = otx_lookup_hash(ioc_value)
        if "error" not in tmp_otx:
            otx_result = tmp_otx

        tmp_vt = vt_lookup_hash(ioc_value)
        if "error" not in tmp_vt:
            vt_result = tmp_vt

        threat_score = calculate_generic_score(
            otx_pulse_count=otx_result["pulse_count"],
            vt_malicious=vt_result["malicious"],
            vt_suspicious=vt_result["suspicious"],
        )

    elif ioc_type == "url":
        tmp_otx = otx_lookup_url(ioc_value)
        if "error" not in tmp_otx:
            otx_result = tmp_otx

        tmp_vt = vt_lookup_url(ioc_value)
        if "error" not in tmp_vt:
            vt_result = tmp_vt

        threat_score = calculate_generic_score(
            otx_pulse_count=otx_result["pulse_count"],
            vt_malicious=vt_result["malicious"],
            vt_suspicious=vt_result["suspicious"],
        )

    else:
        print("Unsupported IOC type")
        return

    verdict = get_verdict(threat_score)

    if verdict == "MALICIOUS":
        verdict_text = "MALICIOUS (High risk)"
    elif verdict == "SUSPICIOUS":
        verdict_text = "SUSPICIOUS"
    else:
        verdict_text = "CLEAN "

    analysis_result = {
        "ioc": ioc_value,
        "type": ioc_type,
        "abuse_confidence_score": abuse_result["abuse_confidence_score"] if abuse_result else 0,
        "otx_pulse_count": otx_result["pulse_count"],
        "otx_reputation": otx_result["reputation"],
        "vt_malicious": vt_result["malicious"],
        "vt_suspicious": vt_result["suspicious"],
        "vt_harmless": vt_result["harmless"],
        "vt_undetected": vt_result["undetected"],
        "vt_reputation": vt_result["reputation"],
        "threat_score": threat_score,
        "verdict": verdict,
    }

    save_result(analysis_result)
    print_analysis_result(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        abuse_result=abuse_result,
        otx_result=otx_result,
        vt_result=vt_result,
        threat_score=threat_score,
        verdict=verdict_text,
    )

if __name__ == "__main__":
    main()