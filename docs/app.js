/* UI for the SQL Injection Login Lab. All work happens in this tab; nothing is sent anywhere. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var SQL = null;
  var form = $("login-form"), inUser = $("in-user"), inPass = $("in-pass");
  var btnRun = $("btn-run"), btnReset = $("btn-reset"), engine = $("engine");
  var history = [];

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function q(s) { return "\u201c" + s + "\u201d"; }
  function show(v) { return v === "" ? "(empty)" : v; }

  // Render the vulnerable SQL: colour by what SQLite treats as string/comment, underline user text.
  function renderVulnSql(pre, username, password) {
    pre.textContent = "";
    var parts = LabCore.vulnerableParts(username, password);
    var sql = parts.map(function (p) { return p.text; }).join("");
    var owner = new Array(sql.length), pos = 0;
    parts.forEach(function (p) { for (var k = 0; k < p.text.length; k++) owner[pos++] = p.user; });
    LabCore.tokenizeForDisplay(sql).forEach(function (tok) {
      var i = tok.start;
      while (i < tok.end) {
        var who = owner[i], j = i;
        while (j < tok.end && owner[j] === who) j++;
        var span = el("span", "t-" + tok.type + (who ? " t-user" : ""), sql.slice(i, j));
        if (who) span.title = "typed in the " + who + " box";
        pre.appendChild(span);
        i = j;
      }
    });
    return sql;
  }

  function isLegit(r, u, p) {
    return r.status === "accepted" && userRows().some(function (row) { return row[1] === u && row[2] === p && row[1] === r.value; });
  }

  function verdict(box, r, legit) {
    box.className = "verdict v-" + (r.status === "accepted" ? (legit ? "ok" : "bypass") : r.status);
    box.textContent = "";
    var big = el("strong", "v-word");
    var small = el("span", "v-detail");
    if (r.status === "accepted") {
      big.textContent = legit ? "ACCEPTED" : "ACCEPTED ⚠";
      small.textContent = legit ? "logged in as " + r.value + " with the right password" : "logged in as " + r.value + " WITHOUT the right password";
    }
    else if (r.status === "denied") { big.textContent = "DENIED"; small.textContent = "no matching user"; }
    else { big.textContent = "SQL ERROR"; small.textContent = "SQLite: " + r.error; }
    box.appendChild(big); box.appendChild(small);
  }

  function userRows() { return LabCore.users(SQL); }

  function explainVuln(r, u, p) {
    var rows = userRows();
    var exact = rows.some(function (row) { return row[1] === u && row[2] === p; });
    var tokens = LabCore.tokenizeForDisplay(r.sql);
    var hasComment = tokens.some(function (t) { return t.type === "comment"; });
    var quoteInInput = u.indexOf("'") !== -1 || p.indexOf("'") !== -1;
    if (r.status === "error") {
      if (/one statement at a time/.test(r.error)) {
        return "SQLite refused to run it: your input added a second SQL statement after a ;. The login crashed instead of answering. That alone tells an attacker their text is being run as SQL.";
      }
      return "SQLite could not even read the query, because the ' in your input ended the quoted value early and left broken SQL behind. The login crashed with an error instead of answering. That tells an attacker their text is being run as SQL.";
    }
    if (r.status === "accepted" && exact) {
      return "Normal match: SQLite found the row whose username is " + q(u) + " and whose password matches, and returned it.";
    }
    if (r.status === "accepted") {
      var steps = ["Bypassed! No correct password was given, but your input rewrote the query:"];
      if (quoteInInput) steps.push("Your ' closed the quoted value early, so the rest of your text ran as SQL code.");
      if (/\bor\b/i.test(u + " " + p)) steps.push("The OR condition is true for every row, so the WHERE clause matched all users.");
      if (/\bunion\b/i.test(u + " " + p)) steps.push("UNION added rows of your own choosing to the result.");
      if (hasComment) steps.push("-- turned the rest into a comment (struck through), so the password check was skipped.");
      steps.push("SQLite returned the first row it found: " + q(String(r.value)) + ".");
      return steps;
    }
    if (quoteInInput) {
      return "Your input changed the query's structure, but the rewritten query still matched no row, so the login said no. Look at the colours above to see how SQLite split it up.";
    }
    if (u === "" && p === "") {
      return "SQLite looked for a user with an empty username and an empty password. There isn't one, so no row came back.";
    }
    var userExists = rows.some(function (row) { return row[1] === u; });
    if (userExists) return "SQLite found the user " + q(u) + ", but the password check failed, so no row came back.";
    return "Your text stayed inside the quotes and was compared as plain text. No user is called " + q(u) + ", so no row came back.";
  }

  function explainSafe(r, u, p) {
    if (r.status === "accepted") {
      return "SQLite compared both values exactly and found the row " + q(u) + " with that password.";
    }
    if (r.status === "error") return "SQLite reported an error: " + r.error;
    var looksLikeSql = /'|--|;|\/\*/.test(u + p);
    var s = "The query's shape never changed. SQLite searched for " +
      (u === "" ? "an empty username" : "a user named exactly " + q(u)) + " with " +
      (p === "" ? "an empty password" : "the password " + q(p)) + " and found none.";
    if (looksLikeSql) s += " The quotes, dashes and SQL words in your input were just characters inside those values, never code.";
    return s;
  }

  function renderDb(v, s) {
    var tbody = $("db-rows");
    tbody.textContent = "";
    userRows().forEach(function (row) {
      var tr = el("tr");
      tr.appendChild(el("td", "", String(row[0])));
      tr.appendChild(el("td", "mono", row[1]));
      tr.appendChild(el("td", "mono", row[2]));
      var td = el("td");
      if (v && v.status === "accepted" && v.value === row[1]) td.appendChild(el("span", "tag " + (v.legit ? "tag-good" : "tag-bad"), "Vulnerable"));
      if (s && s.status === "accepted" && s.value === row[1]) td.appendChild(el("span", "tag tag-good", "Protected"));
      if (!td.childNodes.length) td.textContent = "–";
      tr.appendChild(td);
      tbody.appendChild(tr);
    });
  }

  function pillKind(r) { return r.status === "accepted" ? (r.legit ? "ok" : "bypass") : r.status; }
  function setExplain(box, msg) {
    box.textContent = "";
    if (typeof msg === "string") { box.appendChild(el("p", "", msg)); return; }
    box.appendChild(el("p", "", msg[0]));
    var ol = el("ol", "steps");
    msg.slice(1).forEach(function (m) { ol.appendChild(el("li", "", m)); });
    box.appendChild(ol);
  }
  function word(r) { return r.status === "accepted" ? "accepted as " + r.value : r.status === "denied" ? "denied" : "error"; }

  function addHistory(u, p, v, s) {
    history.unshift({ u: u, p: p, v: v, s: s });
    history = history.slice(0, 8);
    var ol = $("history");
    ol.textContent = "";
    history.forEach(function (h) {
      var li = el("li");
      var inp = el("span", "h-in");
      inp.appendChild(el("code", "", show(h.u)));
      inp.appendChild(document.createTextNode(" / "));
      inp.appendChild(el("code", "", show(h.p)));
      li.appendChild(inp);
      var out = el("span", "h-out");
      out.appendChild(el("span", "pill p-" + pillKind(h.v), "Vulnerable: " + word(h.v)));
      out.appendChild(el("span", "pill p-" + pillKind(h.s), "Protected: " + word(h.s)));
      li.appendChild(out);
      ol.appendChild(li);
    });
    $("history-card").hidden = false;
  }

  function run() {
    if (!SQL) return;
    var u = inUser.value, p = inPass.value;
    var v = LabCore.vulnerableLogin(SQL, u, p);
    var s = LabCore.safeLogin(SQL, u, p);

    v.legit = isLegit(v, u, p); s.legit = isLegit(s, u, p);
    verdict($("v-verdict"), v, v.legit);
    renderVulnSql($("v-sql"), u, p);
    setExplain($("v-explain"), explainVuln(v, u, p));

    verdict($("s-verdict"), s, s.legit);
    $("s-sql").textContent = s.sql;
    $("s-b1").textContent = q(u); $("s-b2").textContent = q(p);
    setExplain($("s-explain"), explainSafe(s, u, p));

    renderDb(v, s);
    addHistory(u, p, v, s);
    var res = $("results");
    var wasHidden = res.hidden;
    res.hidden = false;
    res.classList.remove("flash"); void res.offsetWidth; res.classList.add("flash");
    if (wasHidden || res.getBoundingClientRect().top > window.innerHeight * 0.6) {
      res.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  form.addEventListener("submit", function (e) { e.preventDefault(); run(); });
  btnReset.addEventListener("click", function () {
    form.reset(); inUser.value = ""; inPass.value = "";
    history = []; $("history").textContent = ""; $("history-card").hidden = true;
    $("results").hidden = true;
    if (SQL) renderDb(null, null);
    window.scrollTo({ top: 0, behavior: "smooth" });
    inUser.focus({ preventScroll: true });
  });
  Array.prototype.forEach.call(document.querySelectorAll(".chip"), function (chip) {
    chip.addEventListener("click", function () {
      inUser.value = chip.getAttribute("data-u");
      inPass.value = chip.getAttribute("data-p");
      run();
    });
  });

  if (typeof initSqlJs !== "function" || typeof WebAssembly !== "object") {
    engine.textContent = "This browser can't run the SQLite engine";
    engine.className = "engine failed";
    return;
  }
  initSqlJs({ locateFile: function (f) { return "vendor/" + f; } }).then(function (lib) {
    SQL = lib;
    var ver = new SQL.Database();
    var version = ver.exec("SELECT sqlite_version()")[0].values[0][0];
    ver.close();
    engine.textContent = "SQLite " + version + " ready";
    engine.className = "engine ready";
    btnRun.disabled = false;
    renderDb(null, null);
  }).catch(function (err) {
    engine.textContent = "Couldn't load SQLite: " + (err && err.message ? err.message : err);
    engine.className = "engine failed";
  });
})();
