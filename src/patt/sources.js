// TODO: prune dead sheets
// FIXME: refresh breaks urls


export const PATT_REPO = "https://github.com/swisskyrepo/PayloadsAllTheThings";
export const PATT_RAW_BASE =
  "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master";


export const PATT_SHEETS = {
  xss: [
    { name: "XSS Injection README", web: `${PATT_REPO}/tree/master/XSS%20Injection`, raw: `${PATT_RAW_BASE}/XSS%20Injection/README.md` },
    { name: "XSS Filter Bypass", web: `${PATT_REPO}/blob/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md`, raw: `${PATT_RAW_BASE}/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md` },
    { name: "XSS Common WAF Bypass", web: `${PATT_REPO}/blob/master/XSS%20Injection/3%20-%20XSS%20Common%20WAF%20Bypass.md`, raw: `${PATT_RAW_BASE}/XSS%20Injection/3%20-%20XSS%20Common%20WAF%20Bypass.md` },
    { name: "XSS Polyglot", web: `${PATT_REPO}/blob/master/XSS%20Injection/2%20-%20XSS%20Polyglot.md`, raw: `${PATT_RAW_BASE}/XSS%20Injection/2%20-%20XSS%20Polyglot.md` },
  ],
  sqli: [
    { name: "SQL Injection README", web: `${PATT_REPO}/tree/master/SQL%20Injection`, raw: `${PATT_RAW_BASE}/SQL%20Injection/README.md` },
    { name: "MySQL Injection", web: `${PATT_REPO}/blob/master/SQL%20Injection/MySQL%20Injection.md`, raw: `${PATT_RAW_BASE}/SQL%20Injection/MySQL%20Injection.md` },
    { name: "PostgreSQL Injection", web: `${PATT_REPO}/blob/master/SQL%20Injection/PostgreSQL%20Injection.md`, raw: `${PATT_RAW_BASE}/SQL%20Injection/PostgreSQL%20Injection.md` },
    { name: "MSSQL Injection", web: `${PATT_REPO}/blob/master/SQL%20Injection/MSSQL%20Injection.md`, raw: `${PATT_RAW_BASE}/SQL%20Injection/MSSQL%20Injection.md` },
    { name: "OracleSQL Injection", web: `${PATT_REPO}/blob/master/SQL%20Injection/OracleSQL%20Injection.md`, raw: `${PATT_RAW_BASE}/SQL%20Injection/OracleSQL%20Injection.md` },
    { name: "SQLite Injection", web: `${PATT_REPO}/blob/master/SQL%20Injection/SQLite%20Injection.md`, raw: `${PATT_RAW_BASE}/SQL%20Injection/SQLite%20Injection.md` },
  ],
  ssti: [
    { name: "SSTI README (metodologi Rendered/Error/Boolean/Time/Polyglot)", web: `${PATT_REPO}/tree/master/Server%20Side%20Template%20Injection`, raw: `${PATT_RAW_BASE}/Server%20Side%20Template%20Injection/README.md` },
    { name: "SSTI Python (Jinja2/Django/Tornado/Mako)", web: `${PATT_REPO}/blob/master/Server%20Side%20Template%20Injection/Python.md`, raw: `${PATT_RAW_BASE}/Server%20Side%20Template%20Injection/Python.md` },
    { name: "SSTI PHP (Twig/Smarty/Blade)", web: `${PATT_REPO}/blob/master/Server%20Side%20Template%20Injection/PHP.md`, raw: `${PATT_RAW_BASE}/Server%20Side%20Template%20Injection/PHP.md` },
    { name: "SSTI Java (Freemarker/Velocity/Thymeleaf/JSP)", web: `${PATT_REPO}/blob/master/Server%20Side%20Template%20Injection/Java.md`, raw: `${PATT_RAW_BASE}/Server%20Side%20Template%20Injection/Java.md` },
    { name: "SSTI JavaScript (Nunjucks/EJS/Handlebars/Pug)", web: `${PATT_REPO}/blob/master/Server%20Side%20Template%20Injection/JavaScript.md`, raw: `${PATT_RAW_BASE}/Server%20Side%20Template%20Injection/JavaScript.md` },
    { name: "SSTI Ruby (ERB/Slim/Haml)", web: `${PATT_REPO}/blob/master/Server%20Side%20Template%20Injection/Ruby.md`, raw: `${PATT_RAW_BASE}/Server%20Side%20Template%20Injection/Ruby.md` },
  ],
  cmdi: [
    { name: "Command Injection (chaining + filter bypass + exfil)", web: `${PATT_REPO}/tree/master/Command%20Injection`, raw: `${PATT_RAW_BASE}/Command%20Injection/README.md` },
  ],
  lfi: [
    { name: "File Inclusion (LFI-to-RCE, wrappers)", web: `${PATT_REPO}/tree/master/File%20Inclusion`, raw: `${PATT_RAW_BASE}/File%20Inclusion/README.md` },
    { name: "File Inclusion Wrappers (php://filter, data://, expect://, zip/phar)", web: `${PATT_REPO}/blob/master/File%20Inclusion/Wrappers.md`, raw: `${PATT_RAW_BASE}/File%20Inclusion/Wrappers.md` },
    { name: "Directory Traversal (encoding table + linux/win files)", web: `${PATT_REPO}/tree/master/Directory%20Traversal`, raw: `${PATT_RAW_BASE}/Directory%20Traversal/README.md` },
  ],
  ssrf: [
    { name: "SSRF README (bypass localhost + schemes)", web: `${PATT_REPO}/tree/master/Server%20Side%20Request%20Forgery`, raw: `${PATT_RAW_BASE}/Server%20Side%20Request%20Forgery/README.md` },
    { name: "SSRF Cloud Instances (AWS/GCP/Azure encoding)", web: `${PATT_REPO}/blob/master/Server%20Side%20Request%20Forgery/SSRF-Cloud-Instances.md`, raw: `${PATT_RAW_BASE}/Server%20Side%20Request%20Forgery/SSRF-Cloud-Instances.md` },
  ],
  xxe: [
    { name: "XXE Injection (classic/XInclude/SVG/OOB/billion-laughs)", web: `${PATT_REPO}/tree/master/XXE%20Injection`, raw: `${PATT_RAW_BASE}/XXE%20Injection/README.md` },
  ],
  redirect: [
    { name: "Open Redirect", web: `${PATT_REPO}/tree/master/Open%20Redirect`, raw: `${PATT_RAW_BASE}/Open%20Redirect/README.md` },
  ],
  crlf: [
    { name: "CRLF Injection", web: `${PATT_REPO}/tree/master/CRLF%20Injection`, raw: `${PATT_RAW_BASE}/CRLF%20Injection/README.md` },
  ],
  nosql: [
    { name: "NoSQL Injection ($ne/$regex/$where brute)", web: `${PATT_REPO}/tree/master/NoSQL%20Injection`, raw: `${PATT_RAW_BASE}/NoSQL%20Injection/README.md` },
  ],
  jwt: [
    { name: "JSON Web Token (none/kid/jku/x5u)", web: `${PATT_REPO}/tree/master/JSON%20Web%20Token`, raw: `${PATT_RAW_BASE}/JSON%20Web%20Token/README.md` },
  ],
  graphql: [
    { name: "GraphQL Injection (introspection/mutation)", web: `${PATT_REPO}/tree/master/GraphQL%20Injection`, raw: `${PATT_RAW_BASE}/GraphQL%20Injection/README.md` },
  ],
  cors: [
    { name: "CORS Misconfiguration (reflect/null/expand)", web: `${PATT_REPO}/tree/master/CORS%20Misconfiguration`, raw: `${PATT_RAW_BASE}/CORS%20Misconfiguration/README.md` },
  ],
};


export const PATT_MANDATORY_RULE =
  "HUNTER-PATT-RULE: every active payload must come from PayloadsAllTheThings " +
  "(PATT_SHEETS / PATT_CATALOG / selectPatt). Plain normal payloads are negative " +
  "baseline only, never findings. Every PoC must cite patt_source.";
