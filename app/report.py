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

    print(
        f"Return-Path address: "
        f"{email['header_analysis']['return_path_address']}"
    )

    print("Received headers:")
    for header in email["header_analysis"]["received_headers"]:
        print(f"- {header}")

    if header_analysis["indicators"]:
        report.append("Header indicators:")
        for indicator in header_analysis["indicators"]:
            report.append(f"- {indicator}")
    else:
        report.append("Header indicators: None detected")

    return "\n".join(report)