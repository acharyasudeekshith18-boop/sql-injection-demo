"""Ephemeral toy users: no file-backed database, service, or real credentials."""

from contextlib import contextmanager
import sqlite3
from typing import Iterator


@contextmanager
def toy_database() -> Iterator[sqlite3.Connection]:
    """Yield a fresh, private in-memory database, closed after use."""
    db = sqlite3.connect(":memory:")
    try:
        db.executescript(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            );
            INSERT INTO users (username, password) VALUES
                ('admin', 'paper-crane-42'),
                ('alex', 'sunflower-7');
            """
        )
        yield db
    finally:
        db.close()
