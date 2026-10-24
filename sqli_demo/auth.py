"""Two contrasting authentication queries against toy, in-memory records.

The vulnerable function below is DELIBERATELY UNSAFE. Do not copy it into an app.
Both paths store toy passwords in plaintext only to isolate the SQL concept; real
passwords need a password-hashing algorithm and secure verification.
"""

import sqlite3


def vulnerable_query(username: str, password: str) -> str:
    """UNSAFE: embeds untrusted text in SQL syntax; used only for this lesson."""
    return (
        "SELECT username FROM users "
        f"WHERE username = '{username}' AND password = '{password}' LIMIT 1"
    )


def vulnerable_login(db: sqlite3.Connection, username: str, password: str) -> str | None:
    """Return matched username, or None. Intentionally injectable."""
    row = db.execute(vulnerable_query(username, password)).fetchone()
    return row[0] if row else None


def safe_login(db: sqlite3.Connection, username: str, password: str) -> str | None:
    """Bind values as data; user input cannot change the query's structure."""
    row = db.execute(
        "SELECT username FROM users WHERE username = ? AND password = ? LIMIT 1",
        (username, password),
    ).fetchone()
    return row[0] if row else None
