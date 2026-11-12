
from fastapi import FastAPI, UploadFile, File, HTTPException
import tempfile
import os
from app.schemas import AnalyzeResponse
from app.analyzer import analyze_email
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
app = FastAPI(
    title="Phishing Email Analyzer API",
    description="API for analyzing suspicious phishing emails",
    version="1.0.0",
)


@app.get("/")
def home():
    return {
        "message": "Phishing Email Analyzer API is running"
    }



def sanitize_result(result):
    sanitized = result.copy()

    sanitized_attachments = []

    for attachment in result.get("attachments", []):
        safe_attachment = {
            key: value
            for key, value in attachment.items()
            if key != "payload"
        }

        sanitized_attachments.append(safe_attachment)

    sanitized["attachments"] = sanitized_attachments

    return sanitized

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_uploaded_email(file: UploadFile = File(...)):

    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported"
        )
    

    
    if file.size == 0:
        raise HTTPException(
        status_code=400,
        detail="Uploaded email file is empty"
    )

    temp_path = None
    file_size = 0
    
    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".eml"
        ) as temp_file:
            temp_path = temp_file.name  
            while chunk := await file.read(1024 * 1024):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File size exceeds the 10 MB limit"
                    )

                temp_file.write(chunk)


        result = analyze_email(temp_path)

        return sanitize_result(result)

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Email analysis failed"
        )

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

        await file.close()


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }

