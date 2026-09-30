from app.eml_parser import parse_eml

email = parse_eml("samples/test_email.eml")

assert email["from"] == "Microsoft Support <support@example.com>"
assert email["to"] == "user@example.com"
assert email["reply_to"] == "attacker@evil.com"
assert email["subject"] == "Your account is suspended"
assert "account has been suspended" in email["body"]

print("Parser test passed!")