
from app.content_analyzer import analyze_content


def test_detects_urgency():
    result = analyze_content("URGENT: Act now!")
    assert len(result["urgency_indicators"]) == 2


def test_no_urgency():
    result = analyze_content("Hello, here is your weekly newsletter.")
    assert result["urgency_indicators"] == []


def test_empty_body():
    result = analyze_content("")
    assert result["urgency_indicators"] == []


def test_detects_credential_requests():
    result = analyze_content("Please enter your password and share your OTP.")
    assert len(result["credential_indicators"]) == 2


def test_detects_impersonation_language():
    result = analyze_content("Contact Microsoft support for help.")
    assert len(result["impersonation_indicators"]) == 1


if __name__ == "__main__":
    test_detects_urgency()
    test_no_urgency()
    test_empty_body()
    test_detects_credential_requests()
    test_detects_impersonation_language()
    print("All content analyzer tests passed.")
