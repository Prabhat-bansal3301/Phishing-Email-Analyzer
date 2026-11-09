
import os
from urllib import response
import requests


VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"


def get_file_report(sha256):
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        raise RuntimeError("VirusTotal API key is not configured.")

    if not sha256:
        raise ValueError("SHA-256 hash is required.")

    url = f"{VIRUSTOTAL_API_URL}/files/{sha256}"

    headers = {
        "x-apikey": api_key
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=15
    )

    if response.status_code == 404:
        return {"status": "not_found"}

    if response.status_code == 429:
        return {"status": "rate_limited"}

    if response.status_code == 401:
        return {"status": "unauthorized"}

    if response.status_code == 403:
        return {"status": "forbidden"}

    response.raise_for_status()

    data = response.json()

    attributes = data.get("data", {}).get("attributes", {})

    stats = attributes.get("last_analysis_stats", {})

    return {
        "status": "success",
        "stats": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "unsupported": stats.get("type-unsupported", 0),
            "total_engines": sum(stats.values()),
        }
    }
