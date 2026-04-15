from __future__ import annotations

import argparse
import concurrent.futures

from client.api import ApiClient


def send_one(base_url: str, sender_email: str, password: str, recipient: str, index: int) -> dict:
    client = ApiClient(base_url)
    try:
        try:
            client.register(sender_email, password)
        except Exception:
            pass
        client.login(sender_email, password)
        return client.send_mail([recipient], f"Load Test {index}", f"Message {index}")
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["many_users", "one_user"], required=True)
    parser.add_argument("--users", type=int, required=True)
    parser.add_argument("--mails", type=int, required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:8443")
    parser.add_argument("--recipient", default="bob@b.test")
    args = parser.parse_args()

    jobs = []
    if args.mode == "many_users":
        for user_index in range(args.users):
            jobs.append((f"load{user_index}@a.test", "demo123", 1))
    else:
        jobs = [("burst@a.test", "demo123", args.mails)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, max(1, len(jobs)))) as pool:
        futures = []
        for sender_email, password, count in jobs:
            for i in range(count):
                futures.append(pool.submit(send_one, args.base_url, sender_email, password, args.recipient, i))
        results = [future.result() for future in concurrent.futures.as_completed(futures)]
    print(f"Completed {len(results)} send operations.")


if __name__ == "__main__":
    main()
