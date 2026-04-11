from __future__ import annotations


def choose_reply_text(message: dict, suggestion_index: int | None, explicit_text: str | None) -> str:
    if explicit_text:
        return explicit_text
    suggestions = message.get("quick_replies", [])
    if suggestion_index is not None and 0 <= suggestion_index < len(suggestions):
        return suggestions[suggestion_index]
    if suggestions:
        return suggestions[0]
    return "Received, thank you."

