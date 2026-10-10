// TODO: score waf higher
// FIXME: waf guess false positives


import { PATT_CATALOG } from "./catalog.js";


const TECH_PRIORITY = {
  php: ["php", "mysql", "twig", "smarty", "blade", "laravel", "wordpress"],
  wordpress: ["wordpress", "php", "mysql"],
  laravel: ["laravel", "blade", "php"],
  java: ["java", "freemarker", "velocity", "oracle", "jsp", "thymeleaf"],
  dotnet: ["dotnet", "mssql", "windows"],
  windows: ["windows", "dotnet", "mssql"],
  django: ["django", "python", "jinja2", "pg"],
  python: ["python", "jinja2", "django", "pg"],
  jinja2: ["jinja2", "python", "django"],
  node: ["node", "nunjucks", "nosql"],
  nosql: ["nosql", "node"],
  ruby: ["ruby", "erb"],
  pg: ["pg", "python", "django"],
  mysql: ["mysql", "php"],
  mssql: ["mssql", "dotnet"],
  oracle: ["oracle", "java"],
  sqlite: ["sqlite"],
  graphql: ["graphql"],
  "cloud-aws": ["cloud-aws"],
  "cloud-gcp": ["cloud-gcp"],
};


const CONTEXT_MAP = {
  "html-body-raw": ["html-body-raw", "polyglot"],
  "html-body-text": ["html-body-text", "html-body-raw"],
  "attr-double": ["attr-double", "html-body-raw"],
  "attr-single": ["attr-single", "html-body-raw"],
  "attr-unquoted": ["attr-unquoted", "attr-double", "html-body-raw"],
  "js-string": ["js-string", "js-body"],
  "js-body": ["js-body", "js-string"],
  "tag-text": ["tag-text", "html-body-raw"],
  "html-comment": ["comment-bypass", "html-body-raw"],
  scheme: ["scheme"],
};


const WAF_MAP = {
  cloudflare: ["waf-cloudflare"],
  incapsula: ["waf-incapsula"],
  akamai: ["waf-akamai"],
  wordfence: ["waf-wordfence"],
  fortiweb: ["waf-fortiweb"],
  "space-filter": ["filter-space"],
  "quote-filter": ["filter-quote"],
  "paren-filter": ["filter-paren"],
  "angle-filter": ["filter-angle"],
};

function normArr(v) {
  if (!v) return [];
  return (Array.isArray(v) ? v : [v]).map((s) => String(s).toLowerCase());
}

function scoreEntry(e, { techs, contexts, wafs }) {
  let s = 0;
  const eTechs = normArr(e.techs);
  const eCtx = normArr(e.contexts);
  const eBy = normArr(e.bypasses);

  if (!eTechs.length) s += 1;
  else {
    for (const t of techs) {
      if (eTechs.includes(t)) s += 10;
      for (const [tech, prio] of Object.entries(TECH_PRIORITY)) {
        if (t === tech && eTechs.some((x) => prio.includes(x))) s += 4;
      }
    }
  }
  for (const c of contexts) if (eCtx.includes(c)) s += 8;
  for (const w of wafs) {
    const tags = WAF_MAP[w] || [w];
    if (eBy.some((b) => tags.includes(b))) s += 12;
  }


  return s;
}


export function guessWaf({ headers = {}, body = "" } = {}) {
  const h = JSON.stringify(headers).toLowerCase();
  const b = String(body || "").toLowerCase().slice(0, 20000);
  const hay = h + "\n" + b;
  const out = [];
  if (/cloudflare|__cfduid|cf-ray/.test(hay)) out.push("cloudflare");
  if (/incapsula|incap_ses/.test(hay)) out.push("incapsula");
  if (/akamai/.test(hay)) out.push("akamai");
  if (/wordfence|wfvt_/.test(hay)) out.push("wordfence");
  if (/fortiweb|fortigate/.test(hay)) out.push("fortiweb");
  return out;
}

export function selectPatt({ vuln, techs = [], context = null, waf = [], limit = 12 } = {}) {
  if (!vuln) throw new Error("selectPatt: vuln required (xss|sqli|ssti|cmdi|lfi|ssrf|xxe|redirect|crlf|nosql|jwt|graphql|cors)");
  const v = String(vuln).toLowerCase();
  const t = normArr(techs);
  const w = normArr(waf);
  const c = context ? normArr(context).flatMap((x) => CONTEXT_MAP[x] || [x]) : [];
  const pool = PATT_CATALOG.filter((e) => e.vuln === v);
  if (!pool.length) return [];
  const ranked = pool
    .map((e) => ({ e, s: scoreEntry(e, { techs: t, contexts: c, wafs: w }) }))
    .sort((a, b) => b.s - a.s || a.e.id.localeCompare(b.e.id))
    .map((x) => x.e);


  return ranked.slice(0, Math.max(1, limit));
}


export function withCanary(template, canary) {
  return String(template).split("__CANARY__").join(String(canary));
}


const NORMAL_PATTERNS = [
  /^<script>alert\(1\)<\/script>$/i,
  /^' OR 1=1--?$/i,
  /^\.\.\/\.\.\/etc\/passwd$/,
  /^test%0d%0a/i,
];
export function isNormalPayload(payload) {
  const p = String(payload).trim();
  return NORMAL_PATTERNS.some((re) => re.test(p));
}

export function assertPatt({ id = "", template = "", source = "" } = {}) {
  if (!source || !/PayloadsAllTheThings|swisskyrepo/i.test(source)) {
    throw new Error(`assertPatt: ${id} needs PATT patt_source (got: ${source || "(empty)"})`);
  }
  if (isNormalPayload(template)) {
    throw new Error(`assertPatt: ${id} uses plain normal payload — switch to a PATT variant (filter/WAF bypass).`);
  }
  return true;
}


export function mappingSummary() {
  const lines = [];
  lines.push("TECH -> PATT:");
  for (const [tech, prio] of Object.entries(TECH_PRIORITY)) lines.push(`  ${tech} => ${prio.join(", ")}`);
  lines.push("XSS CONTEXT -> KATALOG:");
  for (const [ctx, ks] of Object.entries(CONTEXT_MAP)) lines.push(`  ${ctx} => ${ks.join(", ")}`);
  return lines.join("\n");
}
