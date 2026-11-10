from app.risk_engine import (
    classify_risk,
    score_urls,
    score_headers,
    score_authentication,
    score_content,
    score_html,
    score_attachments,
    score_virustotal,
    calculate_risk,
)


def test_risk_classification():
    assert classify_risk(10) == "Low"
    assert classify_risk(20) == "Medium"
    assert classify_risk(40) == "High"
    assert classify_risk(70) == "Critical"


def test_url_scoring():
    result = score_urls([
        {
            "has_ip_address": True,
            "suspicious_indicators": [
                "Uses HTTP instead of HTTPS"
            ],
        }
    ])

    assert result["score"] == 7
    assert result["max_score"] == 20


def test_header_scoring():
    result = score_headers({
        "indicators": [
            "From and Reply-To domains differ",
            "No Received headers found",
        ]
    })

    assert result["score"] == 10


def test_authentication_scoring():
    result = score_authentication({
        "spf": "fail",
        "dkim": "pass",
        "dmarc": "fail",
    })

    assert result["score"] == 10


def test_content_scoring():
    result = score_content({
        "urgency_indicators": ["Urgent"],
        "credential_indicators": ["Enter password"],
        "impersonation_indicators": ["CEO"],
    })

    assert result["score"] == 15


def test_html_scoring():
    result = score_html([
        "Link uses a javascript: URL",
        "Password input field detected",
    ])

    assert result["score"] == 9


def test_attachment_scoring():
    result = score_attachments([
        {
            "filename": "invoice.exe",
            "indicators": [
                "Potentially risky attachment extension: .exe",
                "File extension and MIME type mismatch: .exe",
            ],
        }
    ])

    assert result["score"] == 10


def test_virustotal_scoring():
    result = score_virustotal([
        {
            "filename": "test.exe",
            "virustotal": {
                "status": "success",
                "stats": {
                    "malicious": 2,
                    "suspicious": 0,
                },
            },
        }
    ])

    assert result["score"] == 10


def test_empty_email_risk():
    result = calculate_risk({})

    assert result["score"] == 0
    assert result["risk_level"] == "Low"


if __name__ == "__main__":
    test_risk_classification()
    test_url_scoring()
    test_header_scoring()
    test_authentication_scoring()
    test_content_scoring()
    test_html_scoring()
    test_attachment_scoring()
    test_virustotal_scoring()
    test_empty_email_risk()

    print("All risk engine tests passed!")