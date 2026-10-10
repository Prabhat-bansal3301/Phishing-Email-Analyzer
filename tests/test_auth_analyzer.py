from app.eml_parser import parse_eml
from app.auth_analyzer import analyze_authentication

email = parse_eml("samples/test_email.eml")
results = analyze_authentication(email["authentication_results"])

assert results["spf"] == "pass"
assert results["dkim"] == "pass"
assert results["dmarc"] == "pass"

print("Authentication analyzer test passed!")

# Test when no authentication headers exist
empty_results = analyze_authentication([])

assert empty_results["spf"] == "not_found"
assert empty_results["dkim"] == "not_found"
assert empty_results["dmarc"] == "not_found"

print("Missing authentication test passed!")

# Test when only SPF is present
partial_results = analyze_authentication([
    "mx.example.net; spf=fail smtp.mailfrom=sender.example"
])

assert partial_results["spf"] == "fail"
assert partial_results["dkim"] == "not_found"
assert partial_results["dmarc"] == "not_found"

print("Partial authentication test passed!")