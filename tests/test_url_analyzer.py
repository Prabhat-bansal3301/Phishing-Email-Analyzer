from app.url_analyzer import analyze_url

result = analyze_url("https://example.com/login")

assert result["domain"] == "example.com"
assert result["scheme"] == "https"
assert result["uses_https"] is True

print("URL analyzer test passed!")

ip_result = analyze_url("http://192.0.2.10/login")
assert ip_result["has_ip_address"] is True

domain_result = analyze_url("https://example.com/login")
assert domain_result["has_ip_address"] is False

print("IP detection test passed!")

http_result = analyze_url("http://example.com/login")
assert "Uses HTTP instead of HTTPS" in http_result["suspicious_indicators"]

subdomain_result = analyze_url("https://login.verify.account.example.com")
assert "Hostname has many subdomains" in subdomain_result["suspicious_indicators"]

print("Suspicious URL indicator tests passed!")

misleading_result = analyze_url(
    "https://trusted.example@attacker.example/login"
)

assert misleading_result["domain"] == "attacker.example"
assert "URL contains embedded user information" in misleading_result["suspicious_indicators"]
print("Misleading URL test passed!")
punycode_result = analyze_url(
    "https://xn--pple-43d.com/login"
)

assert "Hostname contains Punycode" in punycode_result["suspicious_indicators"]

print("Punycode detection test passed!")

encoded_result = analyze_url(
    "https://example.com/%6cogin"
)

assert "URL contains percent-encoded characters" in encoded_result["suspicious_indicators"]

print("URL encoding test passed!")

encoded_result = analyze_url(
    "https://example.com/%6cogin"
)

assert "URL contains percent-encoded characters" in encoded_result["suspicious_indicators"]

print("URL encoding test passed!")

empty_result = analyze_url("")
assert "Missing or invalid hostname" in empty_result["suspicious_indicators"]

relative_result = analyze_url("/login")
assert "Missing or invalid hostname" in relative_result["suspicious_indicators"]

print("URL edge-case tests passed!")

invalid_result = analyze_url("https://exa..mple.com/login")
assert "Hostname has an invalid format" in invalid_result["suspicious_indicators"]

print("Hostname validation test passed!")

invalid_label_result = analyze_url(
    "https://-example.com/login"
)

assert "Hostname has an invalid format" in invalid_label_result["suspicious_indicators"]

print("Invalid hostname label test passed!")

malformed_result = analyze_url("http://[invalid/")

assert "Missing or invalid hostname" in malformed_result["suspicious_indicators"]

print("Malformed URL test passed!")