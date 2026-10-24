"""Command-line simulation; no web server or external target."""

import argparse
import sqlite3

from .auth import safe_login, vulnerable_login, vulnerable_query
from .database import toy_database

PAYLOAD = "' OR 1=1 -- "
WRONG_PASSWORD = "not-the-password"


def demo() -> None:
    print("SQL INJECTION LAB | toy users, in-memory SQLite, local CLI only\n")
    print("Attack input (username):", repr(PAYLOAD))
    print("Wrong password:", repr(WRONG_PASSWORD))
    print("\nVulnerable SQL built from those inputs:")
    print("  " + vulnerable_query(PAYLOAD, WRONG_PASSWORD))
    with toy_database() as db:
        unsafe = vulnerable_login(db, PAYLOAD, WRONG_PASSWORD)
        safe = safe_login(db, PAYLOAD, WRONG_PASSWORD)
    print("\nVulnerable login:", f"ACCEPTED as {unsafe}" if unsafe else "DENIED")
    print("Parameterized login:", f"ACCEPTED as {safe}" if safe else "DENIED")
    print("\nWhy? -- comments out the password check in the unsafe SQL;")
    print("the bound username is just a literal string in the safe query.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m sqli_demo",
        description="Local-only SQL injection simulation. No network or real accounts.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo", help="Run the side-by-side toy injection")
    login = commands.add_parser("login", help="Try your own inputs against toy users")
    login.add_argument("--mode", choices=("safe", "vulnerable"), default="safe")
    login.add_argument("--username", required=True)
    login.add_argument("--password", required=True)
    args = parser.parse_args(argv)
    if args.command == "demo":
        demo()
        return 0
    with toy_database() as db:
        try:
            if args.mode == "vulnerable":
                print("SQL:", vulnerable_query(args.username, args.password))
                matched = vulnerable_login(db, args.username, args.password)
            else:
                print("SQL: SELECT username FROM users WHERE username = ? AND password = ? LIMIT 1")
                matched = safe_login(db, args.username, args.password)
        except sqlite3.Error as exc:
            print(f"Toy SQLite rejected this query: {exc}")
            return 2
    print(f"ACCEPTED as {matched}" if matched else "DENIED")
    return 0
