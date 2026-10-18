
import os
import hashlib  

RISKY_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".msi",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".hta",
    ".iso",
    ".img",
    ".lnk",
}

EXPECTED_MIME_TYPES = {
    ".pdf": {"application/pdf"},
    ".txt": {"text/plain"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".png": {"image/png"},
    ".doc": {"application/msword"},
    ".docx": {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    },
    ".xls": {"application/vnd.ms-excel"},
    ".xlsx": {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    },
    ".zip": {"application/zip", "application/x-zip-compressed"},
    ".exe": {"application/x-msdownload", "application/vnd.microsoft.portable-executable"},
}

def analyze_attachment(attachment):
    filename = attachment.get("filename") or ""
    extension = os.path.splitext(filename)[1].lower()

    indicators = []
    payload = attachment.get("payload", b"")
    sha256 = hashlib.sha256(payload).hexdigest() if payload else None
    if extension in RISKY_EXTENSIONS:
        indicators.append(
            f"Potentially risky attachment extension: '{extension}'"
        )

    content_type = (attachment.get("content_type") or "").lower()
    expected_types = EXPECTED_MIME_TYPES.get(extension)

    if expected_types and content_type and content_type not in expected_types:
        indicators.append(
            f"File extension and MIME type mismatch: "
            f"{extension} declared as {content_type}"
        )

    return {
        "filename": filename,
        "content_type": attachment.get("content_type"),
        "size": attachment.get("size", 0),
        "extension": extension,
        "indicators": indicators,
        "content_type": content_type,
        "sha256": sha256,
    }



