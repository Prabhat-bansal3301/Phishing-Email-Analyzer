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

    return "\n".join(report)