# Phishing Email Analyzer

A full-stack application for inspecting raw `.eml` files and identifying phishing indicators through an explainable risk assessment.

The project includes:

- A **FastAPI backend** for email upload and analysis
- A lightweight **HTML/CSS/JavaScript dashboard**
- Modular analysis for headers, authentication, content, HTML, URLs, and attachments
- A weighted **0–100 risk score** with category breakdowns and explanations
- Optional **VirusTotal** lookups using attachment SHA-256 hashes

> **Use responsibly:** Analyze only emails you are authorized to inspect. This tool is an indicator-based aid, not a definitive verdict.

## Features

### Email analysis

- Parses raw `.eml` files, including multipart messages
- Extracts sender, recipient, subject, body, links, headers, and attachments
- Checks `From`, `Reply-To`, `Return-Path`, and `Received` header relationships
- Reads SPF, DKIM, and DMARC results from `Authentication-Results`
- Detects urgency, credential-request, and impersonation language
- Inspects HTML forms, password inputs, hidden elements, and `javascript:` links

### URL and attachment analysis

- Detects IP-based URLs, Punycode, invalid hostnames, embedded credentials, HTTP links, encoded characters, unexpected schemes, and excessive subdomains
- Flags potentially risky attachment extensions
- Detects extension and MIME-type mismatches
- Calculates SHA-256 hashes for attachments
- Queries VirusTotal by hash when `VT_API_KEY` is configured

### Web application

- Uploads `.eml` files through a browser interface
- Displays risk level, score, indicators, URL findings, attachment findings, and authentication results
- Rejects non-`.eml` files, empty files, malformed messages, and files larger than 10 MB
- Removes raw attachment payloads from API responses

## Risk scoring

The analyzer calculates a score from **0 to 100**:

| Score | Risk level |
| ---: | --- |
| 0–19 | Low |
| 20–39 | Medium |
| 40–69 | High |
| 70–100 | Critical |

Scores are grouped into URL, header, authentication, content, HTML, attachment, and VirusTotal categories. Each category contains its score, maximum score, and explanations for detected indicators.

## Tech stack

- **Backend:** Python, FastAPI, Pydantic, Uvicorn
- **Frontend:** HTML, CSS, vanilla JavaScript
- **Email parsing:** Python standard library
- **Threat intelligence:** VirusTotal API
- **Testing:** pytest and FastAPI `TestClient`

## Getting started

### 1. Clone the repository

```bash
git clone https://github.com/Prabhat-bansal3301/Phishing-Email-Analyzer.git
cd Phishing-Email-Analyzer
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure VirusTotal (optional)

Copy `.env.example` to `.env` and set your API key:

```bash
cp .env.example .env
```

```env
VT_API_KEY=your_virustotal_api_key_here
```

The application does not upload attachment files to VirusTotal. It submits their SHA-256 hashes for lookup. Without an API key, the rest of the analysis still works and VirusTotal is reported as unavailable.

## Run the application

### Start the API

From the repository root:

```bash
uvicorn app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`.

- Health check: `GET /health`
- API status: `GET /`
- Email analysis: `POST /analyze`
- Interactive API documentation: `http://127.0.0.1:8000/docs`

### Start the frontend

In a second terminal, serve the `Frontend` directory:

```bash
cd Frontend
python -m http.server 5500
```

Open [http://127.0.0.1:5500](http://127.0.0.1:5500), choose an `.eml` file, and select **Analyze Email**.

The frontend is configured to call the API at `http://127.0.0.1:8000/analyze`.

## API example

Analyze an email with `curl`:

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -F "file=@samples/test_email.eml"
```

The response contains the parsed email data, analyzed URLs and attachments, authentication results, and `risk_assessment`.

## Python usage

The analysis engine can also be used without the web application:

```python
from app.analyzer import analyze_email
from app.report import generate_report

result = analyze_email("samples/test_email.eml")

print(result["risk_assessment"]["risk_level"])
print(result["risk_assessment"]["score"])
print(generate_report(result))
```

## Run tests

```bash
python -m pytest
```

The test suite covers:

- `.eml` parsing and end-to-end analysis
- API health, upload validation, size limits, error handling, and cleanup
- Header and authentication analysis
- Content and HTML indicators
- URL and attachment analysis
- VirusTotal response handling
- Risk scoring and report generation

## Project structure

```text
.
├── app/
│   ├── main.py                 # FastAPI application and upload endpoint
│   ├── analyzer.py             # End-to-end analysis pipeline
│   ├── schemas.py              # API response models
│   ├── eml_parser.py           # Raw email parsing and extraction
│   ├── header_analyzer.py      # Header consistency checks
│   ├── auth_analyzer.py        # SPF, DKIM, and DMARC parsing
│   ├── content_analyzer.py     # Phishing-language detection
│   ├── html_analyzer.py        # Suspicious HTML detection
│   ├── url_analyzer.py         # URL indicator checks
│   ├── attachment_analyzer.py  # Attachment checks and hashing
│   ├── virustotal.py           # Optional VirusTotal integration
│   ├── risk_engine.py          # Scoring and classification
│   └── report.py               # Plain-text report generation
├── Frontend/
│   ├── index.html              # Dashboard page
│   ├── script.js               # Upload and result rendering
│   └── style.css               # Dashboard styling
├── samples/                    # Example .eml files
├── tests/                      # Automated tests
├── .env.example                # Environment variable template
├── requirements.txt            # Python dependencies
└── README.md
```

## Limitations and security notes

- The application does not retrieve or execute URLs.
- Attachments are analyzed as bytes for metadata and hashing; they are not executed.
- URL reputation, DNS, certificate reputation, and sandbox behavior are not evaluated.
- VirusTotal results depend on the availability and accuracy of the external service.
- The default CORS configuration is intended for local development.
- Do not expose this development configuration directly to the public internet without adding authentication, deployment hardening, and a production CORS policy.

## License

No license has been specified yet.
