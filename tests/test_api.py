
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
        response = client.post(
            "/analyze",
            files={
                "file": (
                    "test_email.eml",
                    b"Sample email content",
                    "message/rfc822"
                )
            }
        )

    assert response.status_code == 500
    assert response.json()["detail"] == "Email analysis failed"

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
                    b"Sample email content",
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
    print("All API tests passed!")
