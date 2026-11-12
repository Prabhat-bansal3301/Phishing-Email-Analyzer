
from pydantic import BaseModel, Field


class VirusTotalStatsResponse(BaseModel):
    malicious: int
    suspicious: int
    undetected: int
    harmless: int
    unsupported: int
    total_engines: int


class VirusTotalResponse(BaseModel):
    status: str
    stats: VirusTotalStatsResponse | None = None

class AttachmentResponse(BaseModel):
    filename: str
    content_type: str
    size: int

class AnalyzedAttachmentResponse(BaseModel):
    filename: str
    content_type: str
    size: int
    extension: str
    indicators: list[str]
    sha256: str
    virustotal: VirusTotalResponse


class AuthenticationResponse(BaseModel):
    spf: str
    dkim: str
    dmarc: str


class SummaryResponse(BaseModel):
    total_urls: int
    suspicious_urls: int

class URLAnalysisResponse(BaseModel):
    url: str
    scheme: str
    domain: str | None
    uses_https: bool
    has_ip_address: bool
    suspicious_indicators: list[str]


class RiskCategoryResponse(BaseModel):
    score: int
    max_score: int
    explanations: list[str]


class RiskAssessmentResponse(BaseModel):
    score: int
    max_score: int
    risk_level: str
    categories: dict[str, RiskCategoryResponse]
    explanations: list[str]

class HeaderAnalysisResponse(BaseModel):
    from_address: str
    reply_to_address: str
    return_path_address: str
    indicators: list[str]
    received_headers: list[str]

class ContentAnalysisResponse(BaseModel):
    urgency_indicators: list[str]
    credential_indicators: list[str]
    impersonation_indicators: list[str]


class HTMLAnalysisResponse(BaseModel):
    pass

class AuthenticationResultsResponse(BaseModel):
    spf: str
    dkim: str
    dmarc: str

class AnalyzeResponse(BaseModel):
    from_address: str = Field(alias="from")
    to: str
    reply_to: str
    return_path: str | None
    subject: str
    date: str

    body: str
    html_body: str

    attachments: list[AttachmentResponse]
    urls: list[str]
    authentication_results: list[str]
    received_headers: list[str]

    header_analysis: HeaderAnalysisResponse
    content_analysis: ContentAnalysisResponse
    html_analysis: list[str]
    authentication: AuthenticationResultsResponse

    analyzed_urls: list[URLAnalysisResponse]
    summary: SummaryResponse
    analyzed_attachments: list[AnalyzedAttachmentResponse]

    risk_assessment: RiskAssessmentResponse


