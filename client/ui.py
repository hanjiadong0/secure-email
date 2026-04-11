from __future__ import annotations

from typing import Any


def print_json_block(data: Any) -> None:
    import json

    print(json.dumps(data, indent=2))


def print_messages(messages: list[dict]) -> None:
    if not messages:
        print("No messages.")
        return
    for item in messages:
        print(f"{item['message_id']} | {item['folder']} | {item['from_email']} -> {', '.join(item['to'])}")
        print(f"  Subject: {item['subject']}")
        if item.get("delivery_state"):
            print(f"  Delivery: {item['delivery_state']}")
        if item.get("classification"):
            print(f"  Class: {item['classification']}")
        if item.get("security_flags", {}).get("suspicious"):
            print(f"  Suspicious: score={item['security_flags'].get('phishing_score')}")
        if item.get("quick_replies"):
            print(f"  Quick replies: {', '.join(item['quick_replies'])}")
        if item.get("actions"):
            labels = [action["label"] for action in item["actions"]]
            print(f"  Actions: {', '.join(labels)}")
        if item.get("attachments"):
            names = [attachment["filename"] for attachment in item["attachments"]]
            print(f"  Attachments: {', '.join(names)}")
        print()
