
from html.parser import HTMLParser


class SuspiciousHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.indicators = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)

        # Detect HTML forms that may collect user input
        if tag == "form":
            self.indicators.append("HTML form detected")

        # Detect password input fields
        if tag == "input":
            input_type = attributes.get("type", "").lower()
            if input_type == "password":
                self.indicators.append("Password input field detected")

        # Detect hidden elements
        if "hidden" in attributes:
            self.indicators.append("Hidden HTML element detected")

        style = attributes.get("style", "").lower()
        if "display:none" in style.replace(" ", ""):
            self.indicators.append("Element hidden using CSS")

        if tag == "a":
            href = attributes.get("href", "").strip().lower()
            if href.startswith("javascript:"):
                self.indicators.append(
                    "Link uses a javascript: URL"
                )

def analyze_html(html_content):
    if not html_content:
        return []

    parser = SuspiciousHTMLParser()
    parser.feed(html_content)

    return list(dict.fromkeys(parser.indicators))
