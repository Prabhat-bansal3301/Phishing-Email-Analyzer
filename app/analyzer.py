
from app.url_analyzer import analyze_url


def analyze_email(file_path):
    from app.eml_parser import parse_eml

    email = parse_eml(file_path)

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

    return email
