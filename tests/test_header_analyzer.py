
from app.eml_parser import parse_eml
from app.header_analyzer import analyze_headers

email = parse_eml("samples/test_email.eml")
result = analyze_headers(email)

assert result["from_address"] == "support@example.com"
assert result["reply_to_address"] == "attacker@evil.com"
assert "From and Reply-To domains differ" in result["indicators"]

print("Header analyzer test passed!")

return_path_email = {
    "from": "support@example.com",
    "reply_to": "support@example.com",
    "return_path": "bounce@mailer.net",
}

return_path_result = analyze_headers(return_path_email)

assert return_path_result["return_path_address"] == "bounce@mailer.net"
assert "From and Return-Path domains differ" in return_path_result["indicators"]

print("Return-Path analysis test passed!")

received_email = {
    "from": "support@example.com",
    "reply_to": "support@example.com",
    "return_path": "support@example.com",
    "received_headers": [
        "from mail.example.net by mx.example.com"
    ],
}

received_result = analyze_headers(received_email)

assert received_result["received_headers"] == [
    "from mail.example.net by mx.example.com"
]

print("Received headers test passed!")

missing_received_email = {
    "from": "support@example.com",
    "reply_to": "support@example.com",
    "return_path": "support@example.com",
    "received_headers": [],
}

missing_received_result = analyze_headers(missing_received_email)

assert "No Received headers found" in missing_received_result["indicators"]

print("Missing Received headers test passed!")