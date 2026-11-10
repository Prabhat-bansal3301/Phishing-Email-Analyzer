from app.html_analyzer import analyze_html
from app.auth_analyzer import analyze_authentication
from app.url_analyzer import analyze_url
from app.header_analyzer import analyze_headers
from app.content_analyzer import analyze_content
from app.attachment_analyzer import analyze_attachment
from app.virustotal import get_file_report
import requests
from app.risk_engine import calculate_risk

def analyze_email(file_path):
    from app.eml_parser import parse_eml

    email = parse_eml(file_path)
    header_analysis = analyze_headers(email)
    email["header_analysis"] = header_analysis
    content_analysis = analyze_content(email["body"])
    email["content_analysis"] = content_analysis
    html_analysis = analyze_html(email.get("html_body"))
    email["html_analysis"] = html_analysis

    authentication = analyze_authentication(
        email["authentication_results"]
    )

    email["authentication"] = authentication
    analyzed_urls = []

    for url in email["urls"]:
        analyzed_urls.append(analyze_url(url))

    email["analyzed_urls"] = analyzed_urls

    total_urls = len(analyzed_urls)

    suspicious_urls = [
        result for result in analyzed_urls
        if result["suspicious_indicators"]
    ]

    email["summary"] = {
        "total_urls": total_urls,
        "suspicious_urls": len(suspicious_urls),
    }
    analyzed_attachments = []

    for attachment in email["attachments"]:
        result = analyze_attachment(attachment)

        try:
            result["virustotal"] = get_file_report(
                result["sha256"]
            )

        except RuntimeError:
            result["virustotal"] = {
                "status": "unavailable",
                "message": "VirusTotal API key is not configured.",
            }

        except requests.exceptions.RequestException as error:
            result["virustotal"] = {
                "status": "error",
                "message": str(error),
            }
        analyzed_attachments.append(result)

    email["analyzed_attachments"] = analyzed_attachments
    email["risk_assessment"] = calculate_risk(email)
    return email