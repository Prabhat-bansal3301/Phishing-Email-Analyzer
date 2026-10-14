
from email.utils import parseaddr


def analyze_headers(email):
    from_address = parseaddr(email.get("from") or "")[1]
    reply_to = parseaddr(email.get("reply_to") or "")[1]

    indicators = []

    if from_address and reply_to:
        from_domain = from_address.rsplit("@", 1)[-1].lower()
        reply_domain = reply_to.rsplit("@", 1)[-1].lower()

        if from_domain != reply_domain:
            indicators.append("From and Reply-To domains differ")

    return {
        "from_address": from_address,
        "reply_to_address": reply_to,
        "indicators": indicators,
    }
