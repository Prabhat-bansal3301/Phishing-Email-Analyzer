
import logging
import os
import tempfile
from email import policy
from email.parser import BytesParser
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, UploadFile, File, HTTPException

from app.analyzer import analyze_email
from app.schemas import AnalyzeResponse
logger = logging.getLogger(__name__)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
app = FastAPI(
    title="Phishing Email Analyzer API",
    description="API for analyzing suspicious phishing emails",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "null",
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {
        "message": "Phishing Email Analyzer API is running"
    }



def sanitize_result(result):
    sanitized = result.copy()

    for field in ("attachments", "analyzed_attachments"):
        safe_attachments = []

        for attachment in result.get(field, []):
            safe_attachment = {
                key: value
                for key, value in attachment.items()
                if key != "payload"
            }

            safe_attachments.append(safe_attachment)

        sanitized[field] = safe_attachments

    return sanitized


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_uploaded_email(file: UploadFile = File(...)):

    # 1. Validate file extension
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported"
        )

    temp_path = None
    file_size = 0

    try:
        # 2. Save uploaded file in chunks
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".eml"
        ) as temp_file:

            temp_path = temp_file.name

            while chunk := await file.read(1024 * 1024):
                file_size += len(chunk)

                # 3. Enforce 10 MB limit
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File size exceeds the 10 MB limit"
                    )

                temp_file.write(chunk)

        # 4. Reject empty uploads
        if file_size == 0:
            raise HTTPException(
                status_code=400,
                detail="Uploaded email file is empty"
            )

        # 5. Parse email file
        with open(temp_path, "rb") as email_file:
            parsed_email = BytesParser(
                policy=policy.default
            ).parse(email_file)

        # 6. Validate required email headers
        has_sender = bool(parsed_email.get("From"))
        has_subject = bool(parsed_email.get("Subject"))

        if not has_sender:
            raise HTTPException(
                status_code=400,
                detail="Invalid email file: missing From header"
            )

        if not has_subject:
            raise HTTPException(
                status_code=400,
                detail="Invalid email file: missing Subject header"
            )

        # 7. Analyze email
        result = analyze_email(temp_path)

        # 8. Remove sensitive attachment payloads
        return sanitize_result(result)

    except HTTPException:
        raise

    except Exception:
        logger.exception(
            "Unexpected error during email analysis"
        )

        raise HTTPException(
            status_code=500,
            detail="Email analysis failed"
        )

    finally:
        try:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
        except OSError:
            logger.exception("Failed to remove temporary email file")
        finally:
            await file.close()



@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }

