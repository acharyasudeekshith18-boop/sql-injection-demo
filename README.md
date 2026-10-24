# SQL Injection Lab 🧪

A tiny, self-contained Python 3 + SQLite simulation for learning **why string-built SQL is dangerous** and how **parameterized queries** prevent this kind of injection. It compares a deliberately vulnerable toy login against a fixed login using the *same* input.

> **Local-only teaching project.** No server, network calls, external targets, accounts, packages, or persisted user database. Never copy `vulnerable_login` into a real application. Use this only on the bundled toy records.

## What you'll see

```text
Attack username: ' OR 1=1 -- 
Wrong password: not-the-password
Vulnerable login: ACCEPTED as admin
Parameterized login: DENIED
```

The seeded accounts are fictional: `admin` / `paper-crane-42` and `alex` / `sunflower-7`. The database lives in memory and is recreated each run.

## Requirements

Python **3.10+** (standard library only; `sqlite3` ships with most Python installs).

## Run

From the project folder:

```bash
python3 -m sqli_demo demo
```

Try a normal login with the default, safe query:

```bash
python3 -m sqli_demo login --username alex --password sunflower-7
```

Compare the same payload against both modes (the outer double quotes are shell quoting):

```bash
python3 -m sqli_demo login --mode vulnerable --username "' OR 1=1 -- " --password not-the-password
python3 -m sqli_demo login --mode safe       --username "' OR 1=1 -- " --password not-the-password
```

Expected: the first says `ACCEPTED as admin`, the second says `DENIED`. Running the demo prints the complete toy SQL so you can inspect the difference.

## Run the tests

```bash
python3 -m unittest discover -s tests -v
```

The tests check correct credentials, wrong credentials, bypass on the vulnerable path, rejection on the parameterized path, the generated unsafe SQL, fresh database state, and the safe CLI default.

## How it works

The vulnerable path joins user input directly into SQL:

```python
f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}' LIMIT 1"
```

With the username `' OR 1=1 -- `, the resulting query has this shape:

```sql
SELECT username FROM users WHERE username = '' OR 1=1 -- ' AND password = 'not-the-password' LIMIT 1
```

In SQLite, `-- ` begins a comment. The rest of that line—including the password condition—is ignored. `OR 1=1` is true, so SQLite returns the first seeded row (`admin`) even though the supplied password is wrong. This is a simulated authentication bypass, not access to a real account.

The safe path keeps the SQL structure fixed and binds values separately:

```python
db.execute(
    "SELECT username FROM users WHERE username = ? AND password = ? LIMIT 1",
    (username, password),
)
```

SQLite treats the entire payload as a username **value**, not executable SQL. There is no matching username, so login fails. Don't try to fix injection with manual quote escaping or string replacement—use bound parameters. Parameter placeholders protect **values**; if your app dynamically selects table or column names, use an explicit allowlist instead.

**Important distinction:** This lab stores fictional passwords as plaintext only to focus on SQL parsing. Real applications must use a reputable password-hashing scheme (e.g. Argon2id or bcrypt), secure verification, and proper authentication/session design. Parameterization prevents injection; it does **not** make plaintext passwords safe.

## Project layout

```text
sqli_demo/database.py   Fresh in-memory SQLite database and toy users
sqli_demo/auth.py       Vulnerable and parameterized queries
sqli_demo/cli.py        Side-by-side demo and manual input CLI
sqli_demo/__main__.py   python -m entry point
tests/test_auth.py       Standard-library unittest suite
```

### Suggested GitHub description

> A local Python + SQLite SQL injection simulation comparing unsafe string interpolation with parameterized queries, with automated tests and zero dependencies.
