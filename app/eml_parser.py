from email import policy
from email.parser import BytesParser


def parse_eml(file_path):
    with open(file_path, "rb") as file:
        message = BytesParser(policy=policy.default).parse(file)

    body = message.get_body(preferencelist=("plain", "html"))

    return {
        "from": message.get("From"),
        "to": message.get("To"),
        "reply_to": message.get("Reply-To"),
        "return_path": message.get("Return-Path"),
        "subject": message.get("Subject"),
        "date": message.get("Date"),
        "body": body.get_content() if body else None,
    }