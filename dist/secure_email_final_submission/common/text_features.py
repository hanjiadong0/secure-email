from __future__ import annotations

import math
import re
import threading
from collections import Counter

import spacy  # type: ignore


_SPACY_MAX_CHARS = 50_000
_SPACY_NLP = None
_SPACY_LOCK = threading.Lock()


def _get_spacy_nlp():
    global _SPACY_NLP
    if _SPACY_NLP is not None:
        return _SPACY_NLP
    with _SPACY_LOCK:
        if _SPACY_NLP is not None:
            return _SPACY_NLP
        # Use a lightweight tokenizer-only pipeline that doesn't require downloading a model.
        nlp = spacy.blank("en")
        nlp.max_length = max(nlp.max_length, _SPACY_MAX_CHARS + 256)
        _SPACY_NLP = nlp
        return _SPACY_NLP


def tokenize(text: str) -> list[str]:
    if not text:
        return []
    doc = _get_spacy_nlp()(text[:_SPACY_MAX_CHARS])
    tokens: list[str] = []
    for token in doc:
        if token.is_space or token.is_punct:
            continue
        if token.is_stop or token.like_num or token.is_digit:
            continue
        if token.like_url:
            continue
        value = (token.lemma_ or token.text).strip().lower()
        if value in {"http", "https"}:
            continue
        if len(value) < 2:
            continue
        if not any(char.isalnum() for char in value):
            continue
        tokens.append(value)
    return tokens


def extract_keywords(text: str, corpus: list[str], top_k: int = 5) -> list[str]:
    tokens = tokenize(text)
    if not tokens:
        return []
    current = Counter(tokens)
    documents = [set(tokenize(item)) for item in corpus if item.strip()]
    doc_count = len(documents) or 1
    scored: list[tuple[float, str]] = []
    for token, freq in current.items():
        document_frequency = sum(1 for doc in documents if token in doc)
        idf = math.log((doc_count + 1) / (document_frequency + 1)) + 1.0
        scored.append((freq * idf, token))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [token for _, token in scored[:top_k]]


def classify_message(keywords: list[str], subject: str, body_text: str) -> str:
    text = " ".join([subject, body_text, " ".join(keywords)]).lower()
    rules = {
        "Finance": {"invoice", "rechnung", "payment", "budget", "bill"},
        "HR": {"candidate", "bewerbung", "interview", "resume", "feedback"},
        "Scheduling": {"meeting", "termin", "deadline", "calendar", "tomorrow"},
        "Security": {"verify", "password", "urgent", "account", "login"},
        "Support": {"issue", "ticket", "bug", "incident", "help"},
    }
    for label, rule_tokens in rules.items():
        if any(token in text for token in rule_tokens):
            return label
    return "General"


def _heuristic_phishing_flags(
    sender_email: str,
    subject: str,
    body_text: str,
    reply_to: str | None = None,
) -> dict:
    text = f"{subject} {body_text}".lower()
    score = 0
    reasons: list[str] = []
    urgency_markers = ["urgent", "immediately", "verify", "password", "payment", "account"]
    if any(marker in text for marker in urgency_markers):
        score += 3
        reasons.append("urgent_or_credentials_language")
    links = re.findall(r"https?://[^\s]+", body_text, flags=re.IGNORECASE)
    if len(links) >= 2:
        score += 1
        reasons.append("multiple_links")
    if "@" in sender_email:
        sender_domain = sender_email.rsplit("@", 1)[1].lower()
        if reply_to and "@" in reply_to and reply_to.rsplit("@", 1)[1].lower() != sender_domain:
            score += 3
            reasons.append("reply_to_domain_mismatch")
    if re.search(r"confirm|reset|click|bank|wire", text):
        score += 2
        reasons.append("action_request_language")
    injection_markers = [
        "ignore previous instructions",
        "ignore all previous",
        "system prompt",
        "developer message",
        "reveal hidden prompt",
        "act as",
        "<script",
        "javascript:",
    ]
    if any(marker in text for marker in injection_markers):
        score += 4
        reasons.append("prompt_or_script_injection_language")
    suspicious = score >= 4
    return {"phishing_score": score, "suspicious": suspicious, "reasons": reasons}


def phishing_flags(
    sender_email: str,
    subject: str,
    body_text: str,
    reply_to: str | None = None,
    model_score: int | None = None,
    model_suspicious: bool | None = None,
    model_reasons: list[str] | None = None,
) -> dict:
    heuristic = _heuristic_phishing_flags(sender_email, subject, body_text, reply_to)
    if model_score is None and model_suspicious is None and not model_reasons:
        return heuristic

    merged_reasons = list(
        dict.fromkeys(
            [
                *heuristic.get("reasons", []),
                *(model_reasons or []),
            ]
        )
    )
    heuristic_score = int(heuristic.get("phishing_score", 0))
    try:
        raw_model_score = int(model_score or 0)
    except (TypeError, ValueError):
        raw_model_score = 0
    bounded_model_score = max(0, min(10, raw_model_score))
    suspicious = bool(heuristic.get("suspicious")) or bool(model_suspicious) or bounded_model_score >= 6
    score = max(heuristic_score, bounded_model_score)
    return {
        "phishing_score": score,
        "suspicious": suspicious,
        "reasons": merged_reasons,
    }


def _heuristic_quick_reply_suggestions(subject: str, body_text: str) -> list[str]:
    text = f"{subject} {body_text}".lower()
    suggestions: list[str] = []
    if "?" in body_text or "can you" in text or "could you" in text:
        suggestions.extend(["Yes, that works for me.", "I need a bit more information.", "What is the deadline?"])
    if any(term in text for term in ["tomorrow", "today", "meeting", "deadline", "date"]):
        suggestions.extend(["I confirm the schedule.", "Please move this to a later time."])
    if "thanks" in text or "thank you" in text:
        suggestions.append("Thanks, received.")
    if not suggestions:
        suggestions.extend(["Received, thank you.", "I will follow up shortly."])
    unique: list[str] = []
    for item in suggestions:
        if item not in unique:
            unique.append(item)
    return unique[:4]


def quick_reply_suggestions(
    subject: str,
    body_text: str,
    model_suggestions: list[str] | None = None,
) -> list[str]:
    if model_suggestions:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in model_suggestions:
            if not isinstance(item, str):
                continue
            value = item.strip()
            if not value or value in seen:
                continue
            seen.add(value)
            cleaned.append(value[:180])
        if cleaned:
            return cleaned[:4]
    return _heuristic_quick_reply_suggestions(subject, body_text)


def apply_model_quick_replies(subject: str, body_text: str, model_suggestions: list[str] | None) -> list[str]:
    return quick_reply_suggestions(subject, body_text, model_suggestions)


def levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, char_left in enumerate(left, start=1):
        current = [i]
        for j, char_right in enumerate(right, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (char_left != char_right)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def fuzzy_score(query: str, candidate: str) -> float:
    q = query.strip().lower()
    c = candidate.strip().lower()
    if not q or not c:
        return 0.0
    if q in c:
        return 1.0
    distance = levenshtein(q, c)
    scale = max(len(q), len(c))
    return max(0.0, 1.0 - (distance / scale))
