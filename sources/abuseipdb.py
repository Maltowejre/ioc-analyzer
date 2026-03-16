import requests
from config import ABUSEIPDB_API_KEY

BASE_URL = "https://api.abuseipdb.com/api/v2/check"

def lookup_ip(ip_address: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {
            "source": "AbuseIPDB",
            "error": "ABUSEIPDB_API_KEY is missing"
        }

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            BASE_URL,
            headers=headers,
            params=params,
            timeout=(10, 30)
        )
        response.raise_for_status()

        data = response.json().get("data", {})

        return {
            "source": "AbuseIPDB",
            "ioc": ip_address,
            "type": "ip",
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports", 0),
        }

    except requests.exceptions.HTTPError as e:
        return {
            "source": "AbuseIPDB",
            "error": f"HTTP error: {str(e)}"
        }
    except requests.exceptions.RequestException as e:
        return {
            "source": "AbuseIPDB",
            "error": f"Request error: {str(e)}"
        }