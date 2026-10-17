
import re


def analyze_content(body):
    body = body or ""
    text = body.lower()

    urgency_phrases = [
        "urgent",
        "immediate action required",
        "act now",
        "account will be suspended",
        "account has been suspended",
        "verify immediately",
        "within 24 hours",
        "final warning",
    ]

    credential_phrases = [
        "enter your password",
        "verify your password",
        "confirm your password",
        "provide your credentials",
        "login to your account",
        "sign in to verify",
        "enter your otp",
        "share your otp",
        "verify your identity",
    ]

    impersonation_phrases = [
        "IT support team",
        "your bank",
        "Microsoft support",
        "account security team",
        "CEO",
        "payroll department",
        "technical support",
    ]
    urgency_indicators = []
    credential_indicators = []
    impersonation_indicators = []

    for phrase in urgency_phrases:
        if re.search(r"\b" + re.escape(phrase) + r"\b", text):
            urgency_indicators.append(
                f"Urgency language detected: '{phrase}'"
            )

    for phrase in credential_phrases:
        if re.search(r"\b" + re.escape(phrase) + r"\b", text):
            credential_indicators.append(
                f"Credential request detected: '{phrase}'"
            )

    for phrase in impersonation_phrases:
        if re.search(r"\b" + re.escape(phrase.lower()) + r"\b", text):
            impersonation_indicators.append(
                f"Possible impersonation language detected: '{phrase}'"
            )
    return {
        "urgency_indicators": urgency_indicators,
        "credential_indicators": credential_indicators,
        "impersonation_indicators": impersonation_indicators,
    }
