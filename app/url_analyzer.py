from urllib.parse import urlparse
import ipaddress
import re


def analyze_url(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        scheme = parsed.scheme.lower()
    except ValueError:
        parsed = urlparse("")
        hostname = None
        scheme = ""

    suspicious_indicators = []

    # Detect IP-address hostnames
    try:
        ipaddress.ip_address(hostname)
        has_ip_address = True
    except (ValueError, TypeError):
        has_ip_address = False

    # Check hostname format
    if hostname:
        labels = hostname.split(".")

        invalid_format = (
        " " in hostname
        or ".." in hostname
        or any(
            label.startswith("-") or label.endswith("-")
            for label in labels
            )
        )

        if invalid_format:
            suspicious_indicators.append(
                "Hostname has an invalid format"
        )
    # Detect Punycode hostnames
    if hostname and "xn--" in hostname.lower():
        suspicious_indicators.append(
            "Hostname contains Punycode"
        )

    # Check URL scheme and hostname
    if scheme not in ("http", "https"):
        suspicious_indicators.append(
            "Unexpected URL scheme"
        )

    if not hostname:
        suspicious_indicators.append(
            "Missing or invalid hostname"
        )

    # Detect percent-encoded characters
    if re.search(r"%[0-9a-fA-F]{2}", url):
        suspicious_indicators.append(
            "URL contains percent-encoded characters"
        )

    # Detect @ symbol
    if parsed.username is not None or parsed.password is not None:
        suspicious_indicators.append(
            "URL contains embedded user information"
    )

    # Detect HTTP
    if scheme == "http":
        suspicious_indicators.append(
            "Uses HTTP instead of HTTPS"
        )

    # Detect many subdomains
    if hostname and hostname.count(".") >= 3:
        suspicious_indicators.append(
            "Hostname has many subdomains"
        )

    return {
        "url": url,
        "scheme": scheme,
        "domain": hostname,
        "uses_https": scheme == "https",
        "has_ip_address": has_ip_address,
        "suspicious_indicators": suspicious_indicators,
    }
