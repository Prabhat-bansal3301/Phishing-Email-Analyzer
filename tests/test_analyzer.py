from app.analyzer import analyze_email

email = analyze_email("samples/test_email.eml")

assert len(email["analyzed_urls"]) >= 2

for result in email["analyzed_urls"]:
    assert "domain" in result
    assert "suspicious_indicators" in result

print("Email analysis test passed!")
assert email["summary"]["total_urls"] >= 2
assert email["summary"]["suspicious_urls"] >= 1
assert email["authentication"]["spf"] == "pass"
assert email["authentication"]["dkim"] == "pass"
assert email["authentication"]["dmarc"] == "pass"

print("Authentication integration test passed!")

print("Risk summary test passed!")