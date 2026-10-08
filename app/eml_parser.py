from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
import re

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.links.append(value)

def parse_eml(file_path):
    with open(file_path, "rb") as file:
        message = BytesParser(policy=policy.default).parse(file)

    body = message.get_body(preferencelist=("plain", "html"))

    attachments = []

    for part in message.iter_attachments():
        attachments.append({
            "filename": part.get_filename(),
            "content_type": part.get_content_type(),
            "size": len(part.get_payload(decode=True) or b""),
        })
    urls = []

    for part in message.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            content = part.get_content()

            # URLs visible in text
            urls.extend(re.findall(
                r'https?://[^\s<>"\']+',
                content
            ))

            # URLs inside HTML href attributes
            if part.get_content_type() == "text/html":
                link_parser = LinkParser()
                link_parser.feed(content)
                urls.extend(link_parser.links)
    return {
        "from": message.get("From"),
        "to": message.get("To"),
        "reply_to": message.get("Reply-To"),
        "return_path": message.get("Return-Path"),
        "subject": message.get("Subject"),
        "date": message.get("Date"),
        "body": body.get_content() if body else None,
        "attachments": attachments,
        "urls": list(dict.fromkeys(urls)),
    }