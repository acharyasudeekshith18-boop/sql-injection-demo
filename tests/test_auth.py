"""Tests run without third-party packages or network access."""

import unittest

from sqli_demo.auth import safe_login, vulnerable_login, vulnerable_query
from sqli_demo.cli import PAYLOAD, WRONG_PASSWORD, main
from sqli_demo.database import toy_database


class LoginTests(unittest.TestCase):
    def test_real_toy_credentials_work_in_both_modes(self):
        with toy_database() as db:
            self.assertEqual(vulnerable_login(db, "alex", "sunflower-7"), "alex")
            self.assertEqual(safe_login(db, "alex", "sunflower-7"), "alex")

    def test_wrong_password_is_denied_in_both_modes(self):
        with toy_database() as db:
            self.assertIsNone(vulnerable_login(db, "admin", WRONG_PASSWORD))
            self.assertIsNone(safe_login(db, "admin", WRONG_PASSWORD))

    def test_payload_bypasses_vulnerable_password_check(self):
        with toy_database() as db:
            self.assertEqual(vulnerable_login(db, PAYLOAD, WRONG_PASSWORD), "admin")

    def test_same_payload_fails_when_parameterized(self):
        with toy_database() as db:
            self.assertIsNone(safe_login(db, PAYLOAD, WRONG_PASSWORD))

    def test_unsafe_sql_shows_comment_swallowing_password_clause(self):
        sql = vulnerable_query(PAYLOAD, WRONG_PASSWORD)
        self.assertIn("username = '' OR 1=1 -- ' AND password =", sql)

    def test_database_is_fresh_every_time(self):
        with toy_database() as first:
            first.execute("DELETE FROM users")
            self.assertIsNone(safe_login(first, "admin", "paper-crane-42"))
        with toy_database() as second:
            self.assertEqual(safe_login(second, "admin", "paper-crane-42"), "admin")

    def test_cli_defaults_to_safe_mode(self):
        from contextlib import redirect_stdout
        from io import StringIO

        out = StringIO()
        with redirect_stdout(out):
            code = main(["login", "--username", PAYLOAD, "--password", WRONG_PASSWORD])
        self.assertEqual(code, 0)
        self.assertIn("DENIED", out.getvalue())


if __name__ == "__main__":
    unittest.main()
