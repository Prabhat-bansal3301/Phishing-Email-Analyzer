RISK_WEIGHTS = {
    "urls": 20,
    "headers": 15,
    "authentication": 15,
    "content": 15,
    "html": 10,
    "attachments": 10,
    "virustotal": 15,
}


def classify_risk(score):
    if score < 20:
        return "Low"
    elif score < 40:
        return "Medium"
    elif score < 70:
        return "High"
    else:
        return "Critical"

def score_urls(analyzed_urls):
    score = 0
    explanations = []

    weights = {
        "IP address": 5,
        "Hostname contains Punycode": 5,
        "Hostname has an invalid format": 4,
        "URL contains embedded user information": 5,
        "Uses HTTP instead of HTTPS": 2,
        "Hostname has many subdomains": 3,
        "URL contains percent-encoded characters": 2,
        "Unexpected URL scheme": 5,
        "Missing or invalid hostname": 5,
    }

    for url in analyzed_urls:
        indicators = url.get("suspicious_indicators", [])

        if url.get("has_ip_address"):
            points = weights["IP address"]
            score += points
            explanations.append(
                f"IP-based URL detected (+{points})"
            )

        for indicator in indicators:
            for rule, points in weights.items():
                if rule in indicator:
                    score += points
                    explanations.append(
                        f"{indicator} (+{points})"
                    )
                    break

    score = min(score, RISK_WEIGHTS["urls"])

    return {
        "score": score,
        "max_score": RISK_WEIGHTS["urls"],
        "explanations": explanations,
    }

def score_headers(header_analysis):
    score = 0
    explanations = []

    weights = {
        "From and Reply-To domains differ": 7,
        "From and Return-Path domains differ": 5,
        "No Received headers found": 3,
    }

    indicators = header_analysis.get("indicators", [])

    for indicator in indicators:
        points = weights.get(indicator, 0)

        if points:
            score += points
            explanations.append(
                f"{indicator} (+{points})"
            )

    score = min(score, RISK_WEIGHTS["headers"])

    return {
        "score": score,
        "max_score": RISK_WEIGHTS["headers"],
        "explanations": explanations,
    }

def score_authentication(authentication):
    score = 0
    explanations = []

    weights = {
        "spf": 5,
        "dkim": 5,
        "dmarc": 5,
    }

    for mechanism, points in weights.items():
        status = authentication.get(mechanism, "not_found")

        if status == "fail":
            score += points
            explanations.append(
                f"{mechanism.upper()} authentication failed (+{points})"
            )

    score = min(score, RISK_WEIGHTS["authentication"])

    return {
        "score": score,
        "max_score": RISK_WEIGHTS["authentication"],
        "explanations": explanations,
    }

def score_content(content_analysis):
    score = 0
    explanations = []

    categories = {
        "urgency_indicators": 3,
        "credential_indicators": 7,
        "impersonation_indicators": 5,
    }

    for category, points in categories.items():
        indicators = content_analysis.get(category, [])

        if indicators:
            score += points
            explanations.append(
                f"{category.replace('_', ' ').title()} detected "
                f"({len(indicators)} indicator(s), +{points})"
            )

    score = min(score, RISK_WEIGHTS["content"])

    return {
        "score": score,
        "max_score": RISK_WEIGHTS["content"],
        "explanations": explanations,
    }

def score_html(html_indicators):
    score = 0
    explanations = []

    weights = {
        "Link uses a javascript: URL": 5,
        "Password input field detected": 4,
        "HTML form detected": 3,
        "Hidden HTML element detected": 2,
        "Element hidden using CSS": 2,
    }

    for indicator in html_indicators:
        points = weights.get(indicator, 0)

        if points:
            score += points
            explanations.append(
                f"{indicator} (+{points})"
            )

    score = min(score, RISK_WEIGHTS["html"])

    return {
        "score": score,
        "max_score": RISK_WEIGHTS["html"],
        "explanations": explanations,
    }

def score_attachments(analyzed_attachments):
    score = 0
    explanations = []

    weights = {
        "Potentially risky attachment extension": 6,
        "File extension and MIME type mismatch": 4,
    }

    for attachment in analyzed_attachments:
        for indicator in attachment.get("indicators", []):
            for rule, points in weights.items():
                if rule in indicator:
                    score += points
                    explanations.append(
                        f"{attachment.get('filename', 'Unknown file')}: "
                        f"{indicator} (+{points})"
                    )
                    break

    score = min(score, RISK_WEIGHTS["attachments"])

    return {
        "score": score,
        "max_score": RISK_WEIGHTS["attachments"],
        "explanations": explanations,
    }

def score_virustotal(analyzed_attachments):
    score = 0
    explanations = []

    for attachment in analyzed_attachments:
        virustotal = attachment.get("virustotal", {})

        if virustotal.get("status") != "success":
            continue

        stats = virustotal.get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        filename = attachment.get("filename", "Unknown file")

        if malicious > 0:
            score += 10
            explanations.append(
                f"{filename}: {malicious} malicious detection(s) (+10)"
            )

        elif suspicious > 0:
            score += 5
            explanations.append(
                f"{filename}: {suspicious} suspicious detection(s) (+5)"
            )

    score = min(score, RISK_WEIGHTS["virustotal"])

    return {
        "score": score,
        "max_score": RISK_WEIGHTS["virustotal"],
        "explanations": explanations,
    }

def calculate_risk(email):
    categories = {
        "urls": score_urls(email.get("analyzed_urls", [])),
        "headers": score_headers(email.get("header_analysis", {})),
        "authentication": score_authentication(
            email.get("authentication", {})
        ),
        "content": score_content(email.get("content_analysis", {})),
        "html": score_html(email.get("html_analysis", [])),
        "attachments": score_attachments(
            email.get("analyzed_attachments", [])
        ),
        "virustotal": score_virustotal(
            email.get("analyzed_attachments", [])
        ),
    }

    total_score = sum(
        category["score"] for category in categories.values()
    )

    explanations = []

    for category_name, category in categories.items():
        for explanation in category["explanations"]:
            explanations.append(
                f"[{category_name.upper()}] {explanation}"
            )

    return {
        "score": total_score,
        "max_score": 100,
        "risk_level": classify_risk(total_score),
        "categories": categories,
        "explanations": explanations,
    }