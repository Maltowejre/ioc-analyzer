import requests
from config import OTX_API_KEY

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

def _headers():
    return {
        "X-OTX-API-KEY": OTX_API_KEY,
        "Accept": "application/json"
    }

def _safe_get(url: str) -> dict:
    if not OTX_API_KEY:
        return {"source": "OTX", "error": "OTX_API_KEY is missing"}

    try:
        response = requests.get(url, headers=_headers(), timeout=(10, 30))
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {"source": "OTX", "error": f"HTTP error: {str(e)}"}
    except requests.exceptions.RequestException as e:
        return {"source": "OTX", "error": f"Request error: {str(e)}"}


def _build_result(raw: dict, indicator: str, ioc_type: str) -> dict:
    if "error" in raw:
        return raw

    pulse_info = raw.get("pulse_info", {})
    return {
        "source": "OTX",
        "ioc": indicator,
        "type": ioc_type,
        "pulse_count": pulse_info.get("count", 0),
        "reputation": raw.get("reputation", 0),
        "country_name": raw.get("country_name"),
        "asn": raw.get("asn"),
        "city": raw.get("city"),
    }

def lookup_ip(ip_address: str) -> dict:
    raw = _safe_get(f"{BASE_URL}/IPv4/{ip_address}/general")
    return _build_result(raw, ip_address, "ip")


def lookup_domain(domain: str) -> dict:
    raw = _safe_get(f"{BASE_URL}/domain/{domain}/general")
    return _build_result(raw, domain, "domain")


def lookup_hash(file_hash: str) -> dict:
    raw = _safe_get(f"{BASE_URL}/file/{file_hash}/general")
    return _build_result(raw, file_hash, "hash")

def lookup_url(url: str) -> dict:
    raw = _safe_get(f"{BASE_URL}/url/{url}/general")
    return _build_result(raw, url, "url")