
from app.html_analyzer import analyze_html


def test_detects_html_form():
    result = analyze_html('<form action="https://example.com"></form>')
    assert "HTML form detected" in result


def test_detects_password_input():
    result = analyze_html('<input type="password">')
    assert "Password input field detected" in result


def test_detects_hidden_element():
    result = analyze_html('<div hidden>Hidden content</div>')
    assert "Hidden HTML element detected" in result


def test_detects_css_hidden_element():
    result = analyze_html('<div style="display: none;">Hidden content</div>')
    assert "Element hidden using CSS" in result


def test_empty_html():
    assert analyze_html("") == []


def test_detects_javascript_link():
    result = analyze_html(
        '<a href="javascript:alert(1)">Click here</a>'
    )
    assert "Link uses a javascript: URL" in result

if __name__ == "__main__":
    test_detects_html_form()
    test_detects_password_input()
    test_detects_hidden_element()
    test_detects_css_hidden_element()
    test_empty_html()
    test_detects_javascript_link()
    print("All HTML analyzer tests passed.")
