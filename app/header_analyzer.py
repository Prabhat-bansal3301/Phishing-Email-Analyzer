
from email.utils import parseaddr


def analyze_headers(email):
    from_address = parseaddr(email.get("from") or "")[1]
    reply_to = parseaddr(email.get("reply_to") or "")[1]
    return_path = parseaddr(email.get("return_path") or "")[1]
    received_headers = email.get("received_headers", [])
    indicators = []

    # Compare From and Reply-To domains
    if from_address and reply_to:
        from_domain = from_address.rsplit("@", 1)[-1].lower()
        reply_domain = reply_to.rsplit("@", 1)[-1].lower()

        if from_domain != reply_domain:
            indicators.append("From and Reply-To domains differ")

    # Compare From and Return-Path domains
    if from_address and return_path:
        from_domain = from_address.rsplit("@", 1)[-1].lower()
        return_path_domain = return_path.rsplit("@", 1)[-1].lower()

        if from_domain != return_path_domain:
            indicators.append("From and Return-Path domains differ")
    
    # Check Received headers
    if not received_headers:
        indicators.append("No Received headers found")
    
    return {
        "from_address": from_address,
        "reply_to_address": reply_to,
        "return_path_address": return_path,
        "indicators": indicators,
        "received_headers": received_headers
    }
