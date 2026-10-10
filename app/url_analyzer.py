from urllib.parse import urlparse
from ipaddress import ip_address

def analyze_url(url):
    parsed = urlparse(url)
    hostname = parsed.hostname

    try:
        ip_address(hostname)
        has_ip_address = True
    except (ValueError, TypeError):
        has_ip_address = False

    suspicious_indicators = []

    if hostname and "@" in url:
        suspicious_indicators.append("Contains @ symbol")

    if parsed.scheme == "http":
        suspicious_indicators.append("Uses HTTP instead of HTTPS")

    if hostname and hostname.count(".") >= 3:
        suspicious_indicators.append("Hostname has many subdomains")

    return {
        "url": url,
        "scheme": parsed.scheme,
        "domain": hostname,
        "uses_https": parsed.scheme == "https",
        "has_ip_address": has_ip_address,
        "suspicious_indicators": suspicious_indicators
    }