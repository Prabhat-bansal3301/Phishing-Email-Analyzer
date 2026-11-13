
from urllib import response

from fastapi.testclient import TestClient
from unittest.mock import patch
import os
from app.main import app
from app.analyzer import analyze_email
client = TestClient(app)


def test_home_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Phishing Email Analyzer API is running"
    }


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy"
    }


def test_analyze_valid_email():
    with open("samples/test_email.eml", "rb") as email_file:
        response = client.post(
            "/analyze",
            files={
                "file": (
                    "test_email.eml",
                    email_file,
                    "message/rfc822"
                )
            }
        )

    assert response.status_code == 200

    result = response.json()

    assert "risk_assessment" in result
    assert "analyzed_urls" in result
    assert "analyzed_attachments" in result


def test_reject_invalid_file():
    response = client.post(
        "/analyze",
        files={
            "file": (
                "test.txt",
                b"This is not an email file",
                "text/plain"
            )
        }
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Only .eml files are supported"


def test_reject_large_file():
    large_content = b"A" * (10 * 1024 * 1024 + 1)

    response = client.post(
        "/analyze",
        files={
            "file": (
                "large_email.eml",
                large_content,
                "message/rfc822"
            )
        }
    )

    assert response.status_code == 413
    assert response.json()["detail"] == (
        "File size exceeds the 10 MB limit"
    )

def test_analysis_failure():
    with patch(
        "app.main.analyze_email",
        side_effect=Exception("Simulated analysis failure")
    ):
        with patch("app.main.logger.exception") as mock_logger:
            response = client.post(
                "/analyze",
                files={
                    "file": (
                        "test_email.eml",
                        b"From: sender@example.com\r\nSubject: Test\r\n\r\nEmail body",
                        "message/rfc822"
                    )
                }
            )

    assert response.status_code == 500
    assert response.json()["detail"] == "Email analysis failed"
    mock_logger.assert_called_once()
    assert "Analyzer unavailable" not in response.text
def test_analyzer_runtime_error():
    with patch(
        "app.main.analyze_email",
        side_effect=RuntimeError("Analyzer unavailable")
    ):
        response = client.post(
            "/analyze",
            files={
                "file": (
                    "test_email.eml",
                    b"From: sender@example.com\r\nSubject: Test\r\n\r\nTest email body",
                    "message/rfc822"
                )
            }
        )

    assert response.status_code == 500
    assert response.json()["detail"] == "Email analysis failed"


def test_empty_email_upload():
    response = client.post(
        "/analyze",
        files={
            "file": (
                "empty.eml",
                b"",
                "message/rfc822"
            )
        }
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Uploaded email file is empty"

def test_temp_file_cleanup():
    captured_path = None

    def mock_analyze_email(file_path):
        nonlocal captured_path
        captured_path = file_path

        assert os.path.exists(file_path)

        return analyze_email(file_path)

    with patch(
        "app.main.analyze_email",
        side_effect=mock_analyze_email
    ):
        response = client.post(
            "/analyze",
            files={
                "file": (
                    "test_email.eml",
                    open("samples/test_email.eml", "rb"),
                    "message/rfc822"
                )
            }
        )

    assert response.status_code == 200
    assert captured_path is not None
    assert not os.path.exists(captured_path)

def test_reject_invalid_email_content():
    response = client.post(
        "/analyze",
        files={
            "file": (
                "fake_email.eml",
                b"This is just a text file, not a valid email",
                "message/rfc822"
            )
        }
    )
    
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid email file: missing From header"
def test_reject_email_without_subject():
    response = client.post(
        "/analyze",
        files={
            "file": (
                "missing_subject.eml",
                b"From: sender@example.com\r\n\r\nEmail body",
                "message/rfc822"
            )
        }
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid email file: missing Subject header"

def test_sanitize_result_removes_payload():
    from app.main import sanitize_result

    sample_result = {
        "attachments": [
            {
                "filename": "invoice.pdf",
                "payload": b"secret file content",
                "size": 100
            }
        ],
        "analyzed_attachments": [
            {
                "filename": "invoice.pdf",
                "payload": b"secret file content",
                "sha256": "abc123"
            }
        ]
    }

    sanitized = sanitize_result(sample_result)

    assert "payload" not in sanitized["attachments"][0]
    assert "payload" not in sanitized["analyzed_attachments"][0]
    assert sanitized["attachments"][0]["filename"] == "invoice.pdf"
    assert sanitized["analyzed_attachments"][0]["sha256"] == "abc123"


if __name__ == "__main__":
    test_home_endpoint()
    test_health_endpoint()
    test_analyze_valid_email()
    test_reject_invalid_file()
    test_reject_large_file()
    test_analysis_failure()
    test_analyzer_runtime_error()
    test_empty_email_upload()
    test_temp_file_cleanup()
    test_reject_invalid_email_content()
    test_reject_email_without_subject()
    test_sanitize_result_removes_payload()
    print("All API tests passed!")
