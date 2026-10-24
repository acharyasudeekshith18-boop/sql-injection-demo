/* SQL Injection Login Lab: core logic shared by the page and the Node tests.
 * Runs real SQLite (sql.js, WebAssembly) entirely in the browser.
 * Mirrors sqli_demo/database.py and sqli_demo/auth.py from this repo.
 * The vulnerable path is DELIBERATELY UNSAFE and exists only for this toy lab. */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.LabCore = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // Same fictional users as sqli_demo/database.py
  var SCHEMA =
    "CREATE TABLE users (\n" +
    "    id INTEGER PRIMARY KEY,\n" +
    "    username TEXT NOT NULL UNIQUE,\n" +
    "    password TEXT NOT NULL\n" +
    ");\n" +
    "INSERT INTO users (username, password) VALUES\n" +
    "    ('admin', 'paper-crane-42'),\n" +
    "    ('alex', 'sunflower-7');";

  var SAFE_SQL = "SELECT username FROM users WHERE username = ? AND password = ? LIMIT 1";

  // Same string-building as auth.vulnerable_query (UNSAFE on purpose)
  function vulnerableQuery(username, password) {
    return "SELECT username FROM users " +
      "WHERE username = '" + username + "' AND password = '" + password + "' LIMIT 1";
  }

  // Pieces of the vulnerable SQL, so the page can mark which characters came from the user
  function vulnerableParts(username, password) {
    return [
      { text: "SELECT username FROM users WHERE username = '", user: false },
      { text: username, user: "username" },
      { text: "' AND password = '", user: false },
      { text: password, user: "password" },
      { text: "' LIMIT 1", user: false }
    ];
  }

  // Python's sqlite3 refuses a second statement after the first one
  // ("You can only execute one statement at a time."). It skips whitespace and comments only.
  function hasMoreSql(tail) {
    var i = 0, n = tail.length;
    while (i < n) {
      var c = tail[i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f") { i++; continue; }
      if (c === "-" && tail[i + 1] === "-") { while (i < n && tail[i] !== "\n") i++; continue; }
      if (c === "/" && tail[i + 1] === "*") {
        var end = tail.indexOf("*/", i + 2);
        if (end === -1) return false;
        i = end + 2; continue;
      }
      return true;
    }
    return false;
  }

  // Python truthiness of row[0], because cli.py prints ACCEPTED only "if matched"
  function pyTruthy(v) {
    if (v === null || v === undefined) return false;
    if (typeof v === "number") return v !== 0;
    if (typeof v === "string") return v.length > 0;
    if (v && v.length !== undefined) return v.length > 0; // blob
    return true;
  }

  function freshDb(SQL) {
    var db = new SQL.Database(); // in-memory, private to this attempt
    db.exec(SCHEMA);
    return db;
  }

  // Run one statement like Python's db.execute(sql, params).fetchone()
  function runOne(db, sql, params) {
    var it = db.iterateStatements(sql);
    var first = it.next();
    if (first.done) throw new Error("No SQL statement to run.");
    var stmt = first.value;
    try {
      if (hasMoreSql(it.getRemainingSQL())) {
        throw new Error("You can only execute one statement at a time.");
      }
      if (params) stmt.bind(params);
      var row = stmt.step() ? stmt.get() : null;
      return row;
    } finally {
      stmt.free();
    }
  }

  function summarize(row, err) {
    if (err) return { status: "error", error: err.message || String(err), row: null, value: null };
    var value = row ? row[0] : null;
    if (row && pyTruthy(value)) return { status: "accepted", value: value, row: row };
    return { status: "denied", value: value, row: row };
  }

  // Vulnerable login: user text pasted into the SQL (auth.vulnerable_login)
  function vulnerableLogin(SQL, username, password) {
    var sql = vulnerableQuery(username, password);
    var db = freshDb(SQL), row = null, err = null;
    try { row = runOne(db, sql, null); } catch (e) { err = e; } finally { db.close(); }
    var out = summarize(row, err); out.sql = sql; return out;
  }

  // Parameterized login: prepared statement + bound values (auth.safe_login)
  function safeLogin(SQL, username, password) {
    var db = freshDb(SQL), row = null, err = null;
    try { row = runOne(db, SAFE_SQL, [username, password]); } catch (e) { err = e; } finally { db.close(); }
    var out = summarize(row, err); out.sql = SAFE_SQL; out.params = [username, password]; return out;
  }

  function users(SQL) {
    var db = freshDb(SQL);
    try { return db.exec("SELECT id, username, password FROM users ORDER BY id")[0].values; }
    finally { db.close(); }
  }

  // DISPLAY ONLY: split SQL text into code / string literal / comment so the page can
  // grey out what SQLite ignored. Results above always come from real SQLite, not from this.
  function tokenizeForDisplay(sql) {
    var out = [], i = 0, n = sql.length, start = 0;
    function push(type, a, b) { if (b > a) out.push({ type: type, start: a, end: b }); }
    while (i < n) {
      var c = sql[i];
      if (c === "'") {
        push("code", start, i);
        var j = i + 1;
        while (j < n) { if (sql[j] === "'") { if (sql[j + 1] === "'") { j += 2; continue; } break; } j++; }
        var close = Math.min(j + 1, n);
        push("string", i, close); i = start = close; continue;
      }
      if (c === "-" && sql[i + 1] === "-") {
        push("code", start, i);
        var e = sql.indexOf("\n", i); if (e === -1) e = n;
        push("comment", i, e); i = start = e; continue;
      }
      if (c === "/" && sql[i + 1] === "*") {
        push("code", start, i);
        var e2 = sql.indexOf("*/", i + 2); e2 = e2 === -1 ? n : e2 + 2;
        push("comment", i, e2); i = start = e2; continue;
      }
      i++;
    }
    push("code", start, n);
    return out;
  }

  return {
    SCHEMA: SCHEMA, SAFE_SQL: SAFE_SQL,
    vulnerableQuery: vulnerableQuery, vulnerableParts: vulnerableParts,
    vulnerableLogin: vulnerableLogin, safeLogin: safeLogin, users: users,
    tokenizeForDisplay: tokenizeForDisplay, hasMoreSql: hasMoreSql
  };
});
