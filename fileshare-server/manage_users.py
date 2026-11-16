#!/usr/bin/env python3
"""Create and manage users (run on the server machine).

    python3 manage_users.py add alice                 # asks for a password
    python3 manage_users.py add root1 --role admin
    python3 manage_users.py list
    python3 manage_users.py passwd alice
    python3 manage_users.py remove alice
    python3 manage_users.py demo-users                # alice, bob, carol, admin

The server re-reads users.json automatically, so you do not need to restart it.
"""

import argparse
import getpass
import sys
from datetime import datetime, timezone
from pathlib import Path

from auth import ROLES, UserStore, hash_password, valid_username

# Passwords for demo-users are deliberately simple.  Lab/demo use ONLY.
DEMO = {
    "alice": ("alice123", "user"),
    "bob": ("bob123", "user"),
    "carol": ("carol123", "user"),
    "admin": ("admin123", "admin"),
}


def ask_password(username):
    first = getpass.getpass(f"Password for {username}: ")
    if len(first) < 4:
        sys.exit("Password must be at least 4 characters")
    if getpass.getpass("Repeat password: ") != first:
        sys.exit("Passwords do not match")
    return first


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Manage file-share users")
    parser.add_argument("--data-dir", default=str(here / "data"))
    commands = parser.add_subparsers(dest="command", required=True)

    add = commands.add_parser("add", help="create a user")
    add.add_argument("username")
    add.add_argument("--password", help="(otherwise you are prompted)")
    add.add_argument("--role", choices=ROLES, default="user")

    commands.add_parser("list", help="show all users")

    remove = commands.add_parser("remove", help="delete a user")
    remove.add_argument("username")

    passwd = commands.add_parser("passwd", help="change a password")
    passwd.add_argument("username")
    passwd.add_argument("--password")

    commands.add_parser("demo-users", help="create alice, bob, carol and admin")

    args = parser.parse_args()
    store = UserStore(Path(args.data_dir) / "users.json")
    users = store.all_users()

    if args.command == "add":
        if not valid_username(args.username):
            sys.exit("Usernames: 2-32 characters, lowercase letters, digits, _ or -")
        if args.username in users:
            sys.exit(f"User {args.username} already exists")
        password = args.password or ask_password(args.username)
        users[args.username] = {
            "password": hash_password(password), "role": args.role,
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        store.save(users)
        print(f"Created {args.role} {args.username}")

    elif args.command == "list":
        if not users:
            print("(no users)")
        for name, record in sorted(users.items()):
            print(f"{name:<20} {record.get('role', 'user'):<6} created {record.get('created', '?')}")

    elif args.command == "remove":
        if users.pop(args.username, None) is None:
            sys.exit(f"No such user: {args.username}")
        store.save(users)
        print(f"Removed {args.username}  (their files stay on the server)")

    elif args.command == "passwd":
        if args.username not in users:
            sys.exit(f"No such user: {args.username}")
        users[args.username]["password"] = hash_password(
            args.password or ask_password(args.username))
        store.save(users)
        print(f"Password changed for {args.username}")

    elif args.command == "demo-users":
        for name, (password, role) in DEMO.items():
            if name not in users:
                users[name] = {
                    "password": hash_password(password), "role": role,
                    "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
                print(f"Created {role:<5} {name:<6} password: {password}")
            else:
                print(f"Exists  {role:<5} {name}")
        store.save(users)


if __name__ == "__main__":
    main()
