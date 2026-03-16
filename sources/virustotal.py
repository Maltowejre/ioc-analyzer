import base64
import requests
from config import VT_API_KEY

BASE_URL = "https://www.virustotal.com/api/v3"

def _headers():
    return {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }

def _extract_stats(data: dict) -> dict:
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attributes.get("reputation", 0),
    }

def _safe_get(url: str) -> dict:
    if not VT_API_KEY:
        return {"source": "VirusTotal", "error": "VT_API_KEY is missing"}

    try:
        response = requests.get(url, headers=_headers(), timeout=(10, 30))
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {"source": "VirusTotal", "error": f"HTTP error: {str(e)}"}
    except requests.exceptions.RequestException as e:
        return {"source": "VirusTotal", "error": f"Request error: {str(e)}"}

def lookup_ip(ip_address: str) -> dict:
    raw = _safe_get(f"{BASE_URL}/ip_addresses/{ip_address}")
    if "error" in raw:
        return raw

    data = raw.get("data", {})
    attributes = data.get("attributes", {})
    result = _extract_stats(data)
    result.update({
        "source": "VirusTotal",
        "ioc": ip_address,
        "type": "ip",
        "country": attributes.get("country"),
        "asn": attributes.get("asn"),
        "as_owner": attributes.get("as_owner"),
    })
    return result

def lookup_domain(domain: str) -> dict:
    raw = _safe_get(f"{BASE_URL}/domains/{domain}")
    if "error" in raw:
        return raw

    data = raw.get("data", {})
    attributes = data.get("attributes", {})
    result = _extract_stats(data)
    result.update({
        "source": "VirusTotal",
        "ioc": domain,
        "type": "domain",
        "categories": attributes.get("categories", {}),
        "creation_date": attributes.get("creation_date"),
        "last_modification_date": attributes.get("last_modification_date"),
    })
    return result

def lookup_hash(file_hash: str) -> dict:
    raw = _safe_get(f"{BASE_URL}/files/{file_hash}")
    if "error" in raw:
        return raw

    data = raw.get("data", {})
    attributes = data.get("attributes", {})
    result = _extract_stats(data)
    result.update({
        "source": "VirusTotal",
        "ioc": file_hash,
        "type": "hash",
        "meaningful_name": attributes.get("meaningful_name"),
        "file_type": attributes.get("type_description"),
    })
    return result

def lookup_url(url: str) -> dict:
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    raw = _safe_get(f"{BASE_URL}/urls/{url_id}")
    if "error" in raw:
        return raw

    data = raw.get("data", {})
    attributes = data.get("attributes", {})
    result = _extract_stats(data)
    result.update({
        "source": "VirusTotal",
        "ioc": url,
        "type": "url",
        "categories": attributes.get("categories", {}),
        "title": attributes.get("title"),
    })
    return result