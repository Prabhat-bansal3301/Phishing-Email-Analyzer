
from app.attachment_analyzer import analyze_attachment
import hashlib

def test_detects_risky_extension():
    result = analyze_attachment({
        "filename": "invoice.exe",
        "content_type": "application/octet-stream",
        "size": 2048,
    })
    assert "Potentially risky attachment extension: '.exe'" in result["indicators"]


def test_calculates_sha256():
    payload = b"test attachment content"

    result = analyze_attachment({
        "filename": "sample.txt",
        "content_type": "text/plain",
        "size": len(payload),
        "payload": payload,
    })

    expected_hash = hashlib.sha256(payload).hexdigest()

    assert result["sha256"] == expected_hash

def test_extension_is_case_insensitive():
    result = analyze_attachment({
        "filename": "SCRIPT.PS1",
        "content_type": "text/plain",
        "size": 100,
    })
    assert result["extension"] == ".ps1"
    assert result["indicators"]


def test_safe_extension_not_flagged():
    result = analyze_attachment({
        "filename": "report.pdf",
        "content_type": "application/pdf",
        "size": 5000,
    })
    assert result["indicators"] == []


def test_missing_filename():
    result = analyze_attachment({
        "filename": None,
        "content_type": "application/octet-stream",
        "size": 0,
    })
    assert result["extension"] == ""
    assert result["indicators"] == []


def test_detects_mime_mismatch():
    result = analyze_attachment({
        "filename": "invoice.pdf",
        "content_type": "application/octet-stream",
        "size": 2048,
    })

    assert any(
        "File extension and MIME type mismatch" in indicator
        for indicator in result["indicators"]
    )


def test_missing_mime_type():
    result = analyze_attachment({
        "filename": "invoice.pdf",
        "content_type": None,
        "size": 2048,
    })

    assert not any(
        "File extension and MIME type mismatch" in indicator
        for indicator in result["indicators"]
    )

def test_detects_double_extension():
    result = analyze_attachment({
        "filename": "invoice.pdf.exe",
        "content_type": "application/octet-stream",
        "size": 2048,
    })

    assert result["extension"] == ".exe"
    assert any(
        "Potentially risky attachment extension" in indicator
        for indicator in result["indicators"]
    )
if __name__ == "__main__":
    test_detects_risky_extension()
    test_extension_is_case_insensitive()
    test_safe_extension_not_flagged()
    test_missing_filename()
    test_detects_mime_mismatch()
    test_missing_mime_type()
    test_calculates_sha256()
    test_detects_double_extension()
    print("All attachment analyzer tests passed.")
