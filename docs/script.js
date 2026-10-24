/* SQL Injection Lab: client-side visualization.
 * Re-creates the behaviour of sqli_demo (Python 3 + sqlite3) with a tiny SQL
 * evaluator for this one SELECT shape. It does NOT run the Python project.
 * Fictional users only; nothing leaves the page. */
(function () {
  "use strict";

  var USERS = [
    { id: 1, username: "admin", password: "paper-crane-42" },
    { id: 2, username: "alex", password: "sunflower-7" }
  ];

  // Built from pieces so the payload is only ever data inside this demo.
  var Q = String.fromCharCode(39);
  var PAYLOAD = Q + " OR 1=1 -- ";
  var WRONG = "not-the-password";

  var SCENARIOS = {
    normal: { user: "alex", pass: "sunflower-7",
      note: "A real user with the right password. Both versions should let alex in." },
    wrong: { user: "alex", pass: WRONG,
      note: "A real user with the wrong password. Both versions should refuse." },
    inject: { user: PAYLOAD, pass: WRONG,
      note: "A crafted username plus a wrong password. Watch what happens to the vulnerable query." }
  };

  /* ---------- tiny SQL tokenizer / parser / evaluator ---------- */
  function tokenize(sql) {
    var toks = [], i = 0, n = sql.length;
    while (i < n) {
      var c = sql[i], s = i;
      if (/\s/.test(c)) { while (i < n && /\s/.test(sql[i])) i++; toks.push({ t: "ws", s: s, e: i }); continue; }
      if (c === "-" && sql[i + 1] === "-") { while (i < n && sql[i] !== "\n") i++; toks.push({ t: "comment", s: s, e: i }); continue; }
      if (c === Q) {
        i++; var val = "";
        while (i < n) {
          if (sql[i] === Q) { if (sql[i + 1] === Q) { val += Q; i += 2; continue; } i++; break; }
          val += sql[i++];
        }
        toks.push({ t: "str", s: s, e: i, v: val }); continue;
      }
      if (/[0-9]/.test(c)) { while (i < n && /[0-9]/.test(sql[i])) i++; toks.push({ t: "num", s: s, e: i, v: Number(sql.slice(s, i)) }); continue; }
      if (/[A-Za-z_]/.test(c)) {
        while (i < n && /[A-Za-z_0-9]/.test(sql[i])) i++;
        var w = sql.slice(s, i), up = w.toUpperCase();
        var kw = ["SELECT", "FROM", "WHERE", "AND", "OR", "LIMIT"].indexOf(up) >= 0;
        toks.push({ t: kw ? "kw" : "id", s: s, e: i, v: kw ? up : w }); continue;
      }
      if (c === "=" || c === "?") { i++; toks.push({ t: c === "?" ? "param" : "op", s: s, e: i, v: c }); continue; }
      i++; toks.push({ t: "other", s: s, e: i, v: c });
    }
    return toks;
  }

  // Grammar: SELECT id FROM id WHERE expr [LIMIT num]
  // expr := and (OR and)* ; and := cmp (AND cmp)* ; cmp := term = term
  function parse(sql) {
    var all = tokenize(sql);
    var toks = all.filter(function (t) { return t.t !== "ws" && t.t !== "comment"; });
    var p = 0, paramIndex = 0;
    function peek() { return toks[p]; }
    function take(type, v) {
      var t = toks[p];
      if (!t || t.t !== type || (v !== undefined && t.v !== v)) throw new Error("syntax error near " + (t ? sql.slice(t.s, t.e) : "end"));
      p++; return t;
    }
    function term() {
      var t = toks[p++];
      if (!t) throw new Error("unexpected end");
      if (t.t === "str" || t.t === "num") return { k: "lit", v: t.v };
      if (t.t === "id") return { k: "col", v: t.v };
      if (t.t === "param") return { k: "param", i: paramIndex++ };
      throw new Error("unexpected " + sql.slice(t.s, t.e));
    }
    function cmp() { var l = term(); take("op", "="); return { k: "eq", l: l, r: term() }; }
    function and() { var x = cmp(); while (peek() && peek().v === "AND") { p++; x = { k: "and", l: x, r: cmp() }; } return x; }
    function or() { var x = and(); while (peek() && peek().v === "OR") { p++; x = { k: "or", l: x, r: and() }; } return x; }
    take("kw", "SELECT"); var col = take("id").v; take("kw", "FROM"); take("id"); take("kw", "WHERE");
    var where = or(), limit = null;
    if (peek() && peek().v === "LIMIT") { p++; limit = take("num").v; }
    if (p !== toks.length) throw new Error("unexpected trailing input");
    var comment = all.filter(function (t) { return t.t === "comment"; })[0] || null;
    return { col: col, where: where, limit: limit, tokens: all, comment: comment };
  }

  function evalNode(node, row, params) {
    switch (node.k) {
      case "lit": return node.v;
      case "col": return row[node.v];
      case "param": return params[node.i];
      case "eq": return evalNode(node.l, row, params) == evalNode(node.r, row, params);
      case "and": return evalNode(node.l, row, params) && evalNode(node.r, row, params);
      case "or": return evalNode(node.l, row, params) || evalNode(node.r, row, params);
    }
    return false;
  }

  function run(sql, params) {
    var q = parse(sql);
    var checks = USERS.map(function (row) { return { row: row, match: !!evalNode(q.where, row, params || []) }; });
    var hit = checks.filter(function (c) { return c.match; })[0];
    return { query: q, checks: checks, user: hit ? hit.row[q.col] : null };
  }

  /* ---------- the two login functions, mirrored from auth.py ---------- */
  function vulnerableQuery(u, p) {
    return "SELECT username FROM users WHERE username = " + Q + u + Q + " AND password = " + Q + p + Q + " LIMIT 1";
  }
  var SAFE_SQL = "SELECT username FROM users WHERE username = ? AND password = ? LIMIT 1";

  /* ---------- rendering ---------- */
  function esc(s) { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }

  // origin[i] is true where the character came from what the user typed
  function renderSql(sql, tokens, origin) {
    var out = "";
    tokens.forEach(function (t) {
      var cls = { kw: "tk-k", str: "tk-s", num: "tk-n", comment: "tk-c", param: "tk-p", id: "tk-i" }[t.t] || "";
      var inner = "", i = t.s;
      if (t.t === "comment") {
        out += '<span class="tk-c"><span class="cm">' + esc(sql.slice(t.s, t.s + 2)) + '</span><span class="cx">' +
          esc(sql.slice(t.s + 2, t.e)) + "</span></span>";
        return;
      }
      while (i < t.e) {
        var o = origin ? origin[i] : false, j = i;
        while (j < t.e && (origin ? origin[j] : false) === o) j++;
        var piece = esc(sql.slice(i, j));
        inner += o ? '<mark class="u">' + piece + "</mark>" : piece;
        i = j;
      }
      out += cls ? '<span class="' + cls + '">' + inner + "</span>" : inner;
    });
    return out;
  }

  function show(s) { return s === "" ? "(empty)" : s; }

  function rowsHtml(checks) {
    return checks.map(function (c) {
      return '<li class="' + (c.match ? "hit" : "miss") + '"><span class="r-name">' + esc(c.row.username) +
        '</span><span class="r-verdict">' + (c.match ? "WHERE is true: match" : "WHERE is false") + "</span></li>";
    }).join("");
  }

  function setResult(el, user) {
    el.dataset.state = user ? "accepted" : "denied";
    el.textContent = user ? "ACCEPTED as " + user : "DENIED";
  }

  var $ = function (id) { return document.getElementById(id); };

  function play(name) {
    var sc = SCENARIOS[name];
    if (!sc) return;
    document.querySelectorAll(".scenario").forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.dataset.scenario === name));
    });
    $("in-user").textContent = sc.user;
    $("in-pass").textContent = sc.pass;
    $("scenario-note").textContent = sc.note;

    // Vulnerable path
    var vsql = vulnerableQuery(sc.user, sc.pass);
    var origin = [], prefix = "SELECT username FROM users WHERE username = " + Q;
    var mid = Q + " AND password = " + Q;
    var k;
    for (k = 0; k < prefix.length; k++) origin.push(false);
    for (k = 0; k < sc.user.length; k++) origin.push(true);
    for (k = 0; k < mid.length; k++) origin.push(false);
    for (k = 0; k < sc.pass.length; k++) origin.push(true);
    while (origin.length < vsql.length) origin.push(false);

    var v = run(vsql);
    $("v-sql").innerHTML = renderSql(vsql, v.query.tokens, origin);
    $("v-rows").innerHTML = rowsHtml(v.checks);
    setResult($("v-result"), v.user);
    var vWhy;
    if (v.query.comment) {
      vWhy = "Your input became part of the SQL. Everything after -- is a comment, so the password check (and LIMIT) never run, and OR 1=1 matches every row. SQLite hands back the first row: " + v.user + ".";
    } else if (v.user) {
      vWhy = "The username and password match a row, so the login is accepted.";
    } else {
      vWhy = "No row has this username and password together, so the login is denied.";
    }
    $("v-why").textContent = vWhy;

    // Parameterized path
    var params = [sc.user, sc.pass];
    var s = run(SAFE_SQL, params);
    $("s-sql").innerHTML = renderSql(SAFE_SQL, s.query.tokens, null);
    $("s-binds").innerHTML =
      '<li><span class="b-key">? #1 username</span><code>' + esc(show(sc.user)) + "</code></li>" +
      '<li><span class="b-key">? #2 password</span><code>' + esc(show(sc.pass)) + "</code></li>";
    $("s-rows").innerHTML = rowsHtml(s.checks);
    setResult($("s-result"), s.user);
    $("s-why").textContent = s.user
      ? "The bound values match a row, so the login is accepted."
      : name === "inject"
        ? "The crafted text is treated as one plain username. No user is literally called that, so the login is denied."
        : "No row has this username and password together, so the login is denied.";

    document.body.dataset.scenario = name;
  }

  document.querySelectorAll(".scenario").forEach(function (b) {
    b.addEventListener("click", function () { play(b.dataset.scenario); });
  });
  var p1 = $("dg-payload"), p2 = $("dg-payload2");
  if (p1) p1.textContent = PAYLOAD;
  if (p2) p2.textContent = PAYLOAD;

  // Start on the injection case so the comparison is visible at a glance.
  play("inject");

  // Exposed for automated checks.
  window.SQLiLab = { run: run, vulnerableQuery: vulnerableQuery, SAFE_SQL: SAFE_SQL, SCENARIOS: SCENARIOS, play: play };
})();
