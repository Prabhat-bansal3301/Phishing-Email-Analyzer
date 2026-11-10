# Phishing Email Analyzer

Phishing Email Analyzer is a Python tool that inspects raw `.eml` files for common phishing signals and returns a structured, explainable risk assessment.

It combines email parsing, header and authentication checks, content and HTML inspection, URL analysis, attachment analysis, and optional VirusTotal lookups.

## What it checks

- **Headers:** `From`, `Reply-To`, `Return-Path`, and `Received` headers
- **Authentication:** SPF, DKIM, and DMARC results from `Authentication-Results`
- **Message content:** urgency, credential-request, and impersonation language
- **HTML:** forms, password fields, hidden elements, CSS-hidden elements, and `javascript:` links
- **URLs:** IP-address hosts, Punycode, invalid hostnames, embedded credentials, HTTP links, encoded characters, unusual schemes, and many subdomains
- **Attachments:** risky extensions, extension/MIME mismatches, file size, and SHA-256 hashes
- **Threat intelligence:** optional VirusTotal file reports for attachment hashes

## Risk scoring

The analyzer calculates a score from **0 to 100** and assigns one of four levels:

| Score | Level |
| ---: | --- |
| 0–19 | Low |
| 20–39 | Medium |
| 40–69 | High |
| 70–100 | Critical |

The result includes category scores, maximum scores, and human-readable explanations for each detected signal.

## Requirements

- Python 3.9+
- `requests`

Install the runtime dependency with:

```bash
python -m pip install requests
```

To run the test suite, install `pytest` as well:

```bash
python -m pip install pytest
```

## Usage

The main entry point is `analyze_email()`. It accepts a path to a raw `.eml` file and returns a dictionary containing the parsed message and all analysis results.

```python
from app.analyzer import analyze_email
from app.report import generate_report

email = analyze_email("samples/test_email.eml")

print(email["risk_assessment"]["risk_level"])
print(email["risk_assessment"]["score"])
print(generate_report(email))
```

The returned dictionary includes:

```python
email["summary"]
email["analyzed_urls"]
email["analyzed_attachments"]
email["header_analysis"]
email["authentication"]
email["content_analysis"]
email["html_analysis"]
email["risk_assessment"]
```

## VirusTotal integration

VirusTotal lookups are optional. Set `VT_API_KEY` before analyzing emails with attachments:

```bash
export VT_API_KEY="your-api-key"
python your_analysis_script.py
```

If the key is not configured, attachment analysis still runs and the VirusTotal result is reported as unavailable. The API is queried by SHA-256 hash; attachment files are not uploaded.

## Running tests

From the repository root:

```bash
python -m pytest
```

The test suite covers parsing, headers, authentication, content, HTML, URLs, attachments, VirusTotal responses, risk scoring, and report generation.

## Project layout

```text
app/
├── analyzer.py             # End-to-end email analysis
├── eml_parser.py           # Raw .eml parsing and URL/attachment extraction
├── header_analyzer.py      # Header consistency checks
├── auth_analyzer.py        # SPF, DKIM, and DMARC extraction
├── content_analyzer.py     # Phishing-language detection
├── html_analyzer.py        # Suspicious HTML detection
├── url_analyzer.py         # URL structure and indicator checks
├── attachment_analyzer.py  # Extension, MIME, and SHA-256 checks
├── virustotal.py           # Optional VirusTotal API integration
├── risk_engine.py          # Scoring and risk classification
└── report.py               # Plain-text report generation
samples/                    # Example .eml input
tests/                      # Automated tests
```

## Limitations

This tool is an indicator-based analysis aid, not a definitive phishing verdict. It does not retrieve or execute links, detonate attachments, validate DNS or certificate reputation, or replace a mail gateway, sandbox, or human review. Treat suspicious messages and attachments as untrusted.

## License

No license has been specified yet.
