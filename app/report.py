
def generate_report(email):
    report = []

    report.append("=== PHISHING EMAIL ANALYSIS REPORT ===")
    report.append(f"From: {email['from']}")
    report.append(f"To: {email['to']}")
    report.append(f"Subject: {email['subject']}")

    report.append("\n=== URL SUMMARY ===")
    report.append(f"Total URLs: {email['summary']['total_urls']}")
    report.append(
        f"URLs with suspicious indicators: "
        f"{email['summary']['suspicious_urls']}"
    )

    report.append("\n=== URL DETAILS ===")

    for result in email["analyzed_urls"]:
        report.append(f"\nURL: {result['url']}")
        report.append(f"Domain: {result['domain']}")
        report.append(f"HTTPS: {result['uses_https']}")

        if result["suspicious_indicators"]:
            report.append("Indicators:")
            for indicator in result["suspicious_indicators"]:
                report.append(f"- {indicator}")
        else:
            report.append("Indicators: None detected")

    report.append("\n=== EMAIL AUTHENTICATION ===")
    authentication = email["authentication"]
    report.append(f"SPF: {authentication['spf']}")
    report.append(f"DKIM: {authentication['dkim']}")
    report.append(f"DMARC: {authentication['dmarc']}")

    report.append("\n=== HEADER ANALYSIS ===")
    header_analysis = email["header_analysis"]

    report.append(f"From address: {header_analysis['from_address']}")
    report.append(f"Reply-To address: {header_analysis['reply_to_address']}")
    report.append(
        f"Return-Path address: {header_analysis['return_path_address']}"
    )

    report.append("Received headers:")
    if header_analysis["received_headers"]:
        for header in header_analysis["received_headers"]:
            report.append(f"- {header}")
    else:
        report.append("- None found")

    if header_analysis["indicators"]:
        report.append("Header indicators:")
        for indicator in header_analysis["indicators"]:
            report.append(f"- {indicator}")
    else:
        report.append("Header indicators: None detected")

    report.append("\n=== EMAIL CONTENT ANALYSIS ===")
    content_analysis = email.get("content_analysis", {})

    for key, label in [
        ("urgency_indicators", "Urgency indicators"),
        ("credential_indicators", "Credential request indicators"),
        ("impersonation_indicators", "Impersonation indicators"),
    ]:
        indicators = content_analysis.get(key, [])
        report.append(f"{label}:")
        if indicators:
            for indicator in indicators:
                report.append(f"- {indicator}")
        else:
            report.append("- None detected")

    report.append("\n=== HTML ANALYSIS ===")
    html_indicators = email.get("html_analysis", [])

    if html_indicators:
        for indicator in html_indicators:
            report.append(f"- {indicator}")
    else:
        report.append("HTML indicators: None detected")

    return "\n".join(report)
