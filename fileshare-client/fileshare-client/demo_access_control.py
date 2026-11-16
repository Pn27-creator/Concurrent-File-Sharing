#!/usr/bin/env python3
"""A scripted walk through the access-control rules, handy for a live demo.

Needs the demo users on the server:   python3 manage_users.py demo-users

    python3 demo_access_control.py --host 127.0.0.1
    python3 demo_access_control.py --host 10.0.0.100        # e.g. inside Mininet

Every step is a real request to the server; "ALLOWED" / "DENIED" is the
server's own decision, not something this script decides.
"""

import argparse
import sys
import tempfile
import uuid
from pathlib import Path

from client import FileShareClient, FileShareError
from protocol import DEFAULT_PORT

PASSWORDS = {"alice": "alice123", "bob": "bob123", "carol": "carol123", "admin": "admin123"}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--cafile")
    args = parser.parse_args()

    def login(user):
        c = FileShareClient(args.host, args.port, tls=args.tls, cafile=args.cafile)
        c.connect()
        c.login(user, PASSWORDS[user])
        return c

    try:
        alice, bob, carol, admin = (login(u) for u in ("alice", "bob", "carol", "admin"))
    except (FileShareError, OSError) as error:
        sys.exit(f"Could not log in the demo users ({error}).\n"
                 "Run 'python3 manage_users.py demo-users' on the server first.")

    tag = uuid.uuid4().hex[:5]
    plan, poster = f"plan-{tag}.txt", f"poster-{tag}.txt"
    workdir = Path(tempfile.mkdtemp(prefix="fileshare-demo-"))
    (workdir / plan).write_text("alice's private plan\n")
    (workdir / poster).write_text("a poster anyone may read\n")

    step_no = [0]
    results = []

    def step(title):
        step_no[0] += 1
        print(f"\n{step_no[0]}. {title}")

    def attempt(who, label, fn, expect_allowed):
        try:
            fn()
            outcome = "ALLOWED"
        except FileShareError as error:
            outcome = f"DENIED  ({error})"
        good = outcome.startswith("ALLOWED") == expect_allowed
        results.append(good)
        print(f"   {who:<6} {label:<42} -> {outcome:<60} {'ok' if good else 'UNEXPECTED'}")

    def dl(client, ref):
        return lambda: client.download(ref, dest=workdir / f"got-{uuid.uuid4().hex[:6]}")

    step(f"alice uploads {plan} (private) and {poster} (public)")
    alice.upload(workdir / plan, visibility="private")
    alice.upload(workdir / poster, visibility="public")
    print("   done")

    step("What can each user see?  (the server filters the listing)")
    for name, c in (("alice", alice), ("bob", bob), ("carol", carol), ("admin", admin)):
        mine = sorted(f["ref"] for f in c.list_files() if tag in f["ref"])
        print(f"   {name:<6} sees: {', '.join(mine) or '-'}")

    step("Download attempts on a PRIVATE file")
    attempt("alice", f"download alice/{plan} (owner)", dl(alice, f"alice/{plan}"), True)
    attempt("bob", f"download alice/{plan}", dl(bob, f"alice/{plan}"), False)
    attempt("carol", f"download alice/{plan}", dl(carol, f"alice/{plan}"), False)
    attempt("admin", f"download alice/{plan} (admin role)", dl(admin, f"alice/{plan}"), True)

    step("Download attempts on a PUBLIC file")
    attempt("bob", f"download alice/{poster}", dl(bob, f"alice/{poster}"), True)

    step(f"alice shares {plan} with carol only")
    alice.share(plan, "carol")
    attempt("carol", f"download alice/{plan} (shared)", dl(carol, f"alice/{plan}"), True)
    attempt("bob", f"download alice/{plan} (not shared)", dl(bob, f"alice/{plan}"), False)

    step("alice stops sharing")
    alice.unshare(plan, "carol")
    attempt("carol", f"download alice/{plan}", dl(carol, f"alice/{plan}"), False)

    step("Managing someone else's file")
    attempt("bob", f"delete alice/{plan}", lambda: bob.delete(f"alice/{plan}"), False)
    attempt("bob", f"share alice/{plan} with bob", lambda: bob.share(f"alice/{plan}", "bob"), False)

    step("Clean up")
    alice.delete(plan)
    alice.delete(poster)
    for c in (alice, bob, carol, admin):
        c.quit()
    for p in workdir.glob("*"):
        p.unlink(missing_ok=True)
    workdir.rmdir()
    print("   removed the demo files")

    print(f"\n{sum(results)}/{len(results)} server decisions matched the access rules.")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
