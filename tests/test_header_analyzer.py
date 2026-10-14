
from app.eml_parser import parse_eml
from app.header_analyzer import analyze_headers

email = parse_eml("samples/test_email.eml")
result = analyze_headers(email)

assert result["from_address"] == "support@example.com"
assert result["reply_to_address"] == "attacker@evil.com"
assert "From and Reply-To domains differ" in result["indicators"]

print("Header analyzer test passed!")
