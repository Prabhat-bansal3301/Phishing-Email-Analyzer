from app.analyzer import analyze_email
from app.report import generate_report

email = analyze_email("samples/test_email.eml")
report = generate_report(email)

assert "PHISHING EMAIL ANALYSIS REPORT" in report
assert "URL SUMMARY" in report
assert "URL DETAILS" in report

print(report)
print("\nReport test passed!")