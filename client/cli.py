from __future__ import annotations

import argparse
from dataclasses import asdict

from client.api import ApiClient
from client.quick_reply import choose_reply_text
from client.ui import print_json_block, print_messages


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Secure email CLI")
    parser.add_argument("--base-url", required=True, help="Example: https://127.0.0.1:8443 or http://127.0.0.1:8443")
    sub = parser.add_subparsers(dest="command", required=True)

    reg = sub.add_parser("register")
    reg.add_argument("--email", required=True)
    reg.add_argument("--password", required=True)
    reg.add_argument("--confirm-password", required=True)

    login = sub.add_parser("login")
    login.add_argument("--email", required=True)
    login.add_argument("--password", required=True)

    e2e_init = sub.add_parser("e2e-init")
    e2e_init.add_argument("--email", required=True)

    e2e_key = sub.add_parser("e2e-key")
    e2e_key.add_argument("--email", required=True)

    for name in ["inbox", "sent", "drafts", "todos"]:
        cmd = sub.add_parser(name)
        cmd.add_argument("--email", required=True)

    msg = sub.add_parser("message")
    msg.add_argument("--email", required=True)
    msg.add_argument("--message-id", required=True)

    upload = sub.add_parser("upload")
    upload.add_argument("--email", required=True)
    upload.add_argument("--file", required=True)

    send = sub.add_parser("send")
    send.add_argument("--email", required=True)
    send.add_argument("--to", required=True, help="Comma-separated recipients")
    send.add_argument("--cc", default="")
    send.add_argument("--subject", required=True)
    send.add_argument("--body", required=True)
    send.add_argument("--attachments", default="", help="Comma-separated attachment IDs")
    send.add_argument("--thread-id", default=None)
    send.add_argument("--e2e", action="store_true")

    draft = sub.add_parser("draft")
    draft.add_argument("--email", required=True)
    draft.add_argument("--to", default="")
    draft.add_argument("--cc", default="")
    draft.add_argument("--subject", default="")
    draft.add_argument("--body", default="")
    draft.add_argument("--attachments", default="")
    draft.add_argument("--message-id", default=None)
    draft.add_argument("--send-now", action="store_true")

    recall = sub.add_parser("recall")
    recall.add_argument("--email", required=True)
    recall.add_argument("--message-id", required=True)

    read = sub.add_parser("mark-read")
    read.add_argument("--email", required=True)
    read.add_argument("--message-id", required=True)

    action = sub.add_parser("action")
    action.add_argument("--email", required=True)
    action.add_argument("--token", required=True)

    reply = sub.add_parser("reply")
    reply.add_argument("--email", required=True)
    reply.add_argument("--message-id", required=True)
    reply.add_argument("--text", default=None)
    reply.add_argument("--suggestion-index", type=int, default=None)

    group_create = sub.add_parser("group-create")
    group_create.add_argument("--email", required=True)
    group_create.add_argument("--name", required=True)
    group_create.add_argument("--members", default="")

    group_add = sub.add_parser("group-add")
    group_add.add_argument("--email", required=True)
    group_add.add_argument("--name", required=True)
    group_add.add_argument("--member", required=True)

    group_send = sub.add_parser("group-send")
    group_send.add_argument("--email", required=True)
    group_send.add_argument("--name", required=True)
    group_send.add_argument("--subject", required=True)
    group_send.add_argument("--body", required=True)
    group_send.add_argument("--attachments", default="")

    search = sub.add_parser("search")
    search.add_argument("--email", required=True)
    search.add_argument("--query", required=True)

    autocomplete = sub.add_parser("autocomplete")
    autocomplete.add_argument("--email", required=True)
    autocomplete.add_argument("--query", required=True)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    client = ApiClient(args.base_url, getattr(args, "email", None) if args.command not in {"register", "login"} else None)
    try:
        if args.command == "register":
            print_json_block(client.register(args.email, args.password, args.confirm_password))
        elif args.command == "login":
            print_json_block(client.login(args.email, args.password))
        elif args.command == "e2e-init":
            print_json_block(asdict(client.ensure_e2e_identity()))
        elif args.command == "e2e-key":
            print_json_block(client.my_e2e_key())
        elif args.command == "upload":
            print_json_block(client.upload_attachment(args.file))
        elif args.command == "inbox":
            print_messages(client.inbox())
        elif args.command == "sent":
            print_messages(client.sent())
        elif args.command == "drafts":
            print_messages(client.drafts())
        elif args.command == "todos":
            print_json_block(client.todos())
        elif args.command == "message":
            print_json_block(client.message(args.message_id))
        elif args.command == "send":
            if args.e2e:
                print_json_block(
                    client.send_mail_e2e(
                        to=_split_csv(args.to),
                        cc=_split_csv(args.cc),
                        subject=args.subject,
                        body_text=args.body,
                        thread_id=args.thread_id,
                    )
                )
            else:
                print_json_block(
                    client.send_mail(
                        to=_split_csv(args.to),
                        cc=_split_csv(args.cc),
                        subject=args.subject,
                        body_text=args.body,
                        attachment_ids=_split_csv(args.attachments),
                        thread_id=args.thread_id,
                    )
                )
        elif args.command == "draft":
            print_json_block(
                client.save_draft(
                    to=_split_csv(args.to),
                    cc=_split_csv(args.cc),
                    subject=args.subject,
                    body_text=args.body,
                    attachment_ids=_split_csv(args.attachments),
                    message_id=args.message_id,
                    send_now=args.send_now,
                )
            )
        elif args.command == "recall":
            print_json_block(client.recall(args.message_id))
        elif args.command == "mark-read":
            print_json_block(client.mark_read(args.message_id))
        elif args.command == "action":
            print_json_block(client.execute_action(args.token))
        elif args.command == "reply":
            original = client.message(args.message_id)
            reply_text = choose_reply_text(original, args.suggestion_index, args.text)
            print_json_block(
                client.send_mail(
                    to=[original["from_email"]],
                    subject=f"Re: {original['subject']}",
                    body_text=reply_text,
                    thread_id=original["thread_id"],
                )
            )
        elif args.command == "group-create":
            print_json_block(client.group_create(args.name, _split_csv(args.members)))
        elif args.command == "group-add":
            print_json_block(client.group_add_member(args.name, args.member))
        elif args.command == "group-send":
            print_json_block(client.send_group(args.name, args.subject, args.body, _split_csv(args.attachments)))
        elif args.command == "search":
            result = client.search(args.query)
            print_messages(result["messages"])
            if result["contacts"]:
                print("Contacts:")
                print_json_block(result["contacts"])
        elif args.command == "autocomplete":
            print_json_block(client.autocomplete(args.query))
    finally:
        client.close()


if __name__ == "__main__":
    main()
