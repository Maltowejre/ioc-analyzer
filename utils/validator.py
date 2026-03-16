import ipaddress
import re
from urllib.parse import urlparse

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def is_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False

def is_domain(value: str) -> bool:
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
    return re.match(pattern, value) is not None

def is_hash(value: str) -> bool:
    value = value.lower()
    return bool(
        re.fullmatch(r"[a-f0-9]{32}", value) or
        re.fullmatch(r"[a-f0-9]{40}", value) or
        re.fullmatch(r"[a-f0-9]{64}", value)
    )

def detect_ioc_type(value: str) -> str:
    if is_ip(value):
        return "ip"
    if is_url(value):
        return "url"
    if is_domain(value):
        return "domain"
    if is_hash(value):
        return "hash"
    return "unknown"