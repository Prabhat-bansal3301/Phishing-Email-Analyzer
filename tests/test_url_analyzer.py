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