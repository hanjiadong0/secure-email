from __future__ import annotations

from common.text_features import phishing_flags


def analyze_message(sender_email: str, subject: str, body_text: str) -> dict:
    return phishing_flags(sender_email, subject, body_text)

