
from app.analyzer import analyze_email


def test_email_analysis():
    email = analyze_email("samples/test_email.eml")

    assert len(email["analyzed_urls"]) >= 2

    for result in email["analyzed_urls"]:
        assert "domain" in result
        assert "suspicious_indicators" in result

    assert email["summary"]["total_urls"] >= 2
    assert email["summary"]["suspicious_urls"] >= 1

    print("Email analysis test passed!")


def test_authentication_integration():
    email = analyze_email("samples/test_email.eml")

    assert email["authentication"]["spf"] == "pass"
    assert email["authentication"]["dkim"] == "pass"
    assert email["authentication"]["dmarc"] == "pass"

    print("Authentication integration test passed!")


def test_header_analysis_integration():
    email = analyze_email("samples/test_email.eml")

    assert (
        "From and Reply-To domains differ"
        in email["header_analysis"]["indicators"]
    )

    print("Header analysis integration test passed!")


def test_content_analysis_is_included():
    email = analyze_email("samples/test_email.eml")

    assert "content_analysis" in email
    assert "urgency_indicators" in email["content_analysis"]
    assert "credential_indicators" in email["content_analysis"]
    assert "impersonation_indicators" in email["content_analysis"]

    print("Content analysis integration test passed!")


def test_html_analysis_is_included():
    email = analyze_email("samples/test_email.eml")

    assert "html_analysis" in email
    assert isinstance(email["html_analysis"], list)

    print("HTML analysis integration test passed!")

def test_attachment_analysis_is_included():
    email = analyze_email("samples/test_email.eml")

    assert "analyzed_attachments" in email
    assert len(email["analyzed_attachments"]) >= 1

    for attachment in email["analyzed_attachments"]:
        assert "filename" in attachment
        assert "extension" in attachment
        assert "indicators" in attachment
        assert "sha256" in attachment

if __name__ == "__main__":
    test_email_analysis()
    test_authentication_integration()
    test_header_analysis_integration()
    test_content_analysis_is_included()
    test_html_analysis_is_included()
    test_attachment_analysis_is_included()
    print("All email analyzer integration tests passed!")
