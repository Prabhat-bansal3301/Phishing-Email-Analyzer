from app.eml_parser import parse_eml

email = parse_eml("samples/test_email.eml")

assert email["from"] == "Microsoft Support <support@example.com>"
assert email["to"] == "user@example.com"
assert email["reply_to"] == "attacker@evil.com"
assert email["subject"] == "Your account is suspended"
assert "account has been suspended" in email["body"]

print("Parser test passed!")

assert len(email["attachments"]) == 1
assert email["attachments"][0]["filename"] == "invoice.txt"
assert email["attachments"][0]["content_type"] == "text/plain"

assert "https://example.com/login" in email["urls"]
assert "https://attacker.example/login" in email["urls"]
assert isinstance(email["authentication_results"], list)
assert len(email["authentication_results"]) == 1
assert "spf=pass" in email["authentication_results"][0]

print("Authentication header extraction test passed!")

print("Attachment test passed!")
print("URL extraction test passed!")