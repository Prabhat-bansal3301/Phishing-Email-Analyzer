import re


def analyze_authentication(authentication_results):
    results = {
        "spf": "not_found",
        "dkim": "not_found",
        "dmarc": "not_found",
    }

    for header in authentication_results:
        for mechanism in ("spf", "dkim", "dmarc"):
            match = re.search(
                rf"\b{mechanism}=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
                header,
                re.IGNORECASE,
            )

            if match:
                results[mechanism] = match.group(1).lower()

    return results