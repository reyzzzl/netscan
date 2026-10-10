#!/usr/bin/env node
// TODO: dedupe generated ids
// FIXME: clean wipes manual packs


import fs from "node:fs";
import path from "node:path";
import { PATT_CATALOG } from "../src/patt/catalog.js";
import { withCanary, assertPatt, mappingSummary } from "../src/patt/select.js";
import { PATT_SHEETS } from "../src/patt/sources.js";

const ROOT = path.join(process.cwd(), "templates", "patt");
const args = process.argv.slice(2);

if (args.includes("--map")) {
  console.log(mappingSummary());
  process.exit(0);
}
if (args.includes("--refresh-info")) {
  for (const [vuln, sheets] of Object.entries(PATT_SHEETS)) {
    console.log(`[${vuln}]`);
    for (const s of sheets) console.log(`  ${s.name}\n    web: ${s.web}\n    raw: ${s.raw}`);
  }
  process.exit(0);
}
if (args.includes("--clean")) {
  try { fs.rmSync(ROOT, { recursive: true, force: true }); } catch {}
}

const sq = (s) => `'${String(s).replace(/'/g, "''")}'`;
function write(id, obj) {
  const dir = ROOT;
  fs.mkdirSync(dir, { recursive: true });
  const L = [];
  L.push(`id: ${id}`);
  L.push(`name: ${sq(obj.name)}`);
  L.push(`severity: ${obj.severity}`);
  L.push(`type: ${obj.type}`);
  L.push(`tags:`);
  for (const t of obj.tags) L.push(`  - ${t}`);
  if (obj.requires?.length) { L.push(`requires:`); for (const t of obj.requires) L.push(`  - ${t}`); }
  L.push(`description: ${sq(obj.description)}`);
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
      }
    }
  }
  fs.writeFileSync(path.join(dir, `${id}.yaml`), L.join("\n") + "\n");
}


const PARAMS = {
  xss: ["q", "search", "name", "message", "comment"],
  sqli: ["id", "user", "page"],
  ssti: ["name", "template", "view"],
  cmdi: ["cmd", "exec", "ip", "host"],
  lfi: ["file", "page", "path", "include"],
  ssrf: ["url", "fetch", "image", "redirect_url"],
  xxe: ["xml", "data"],
  redirect: ["next", "url", "redirect"],
  crlf: ["name", "q", "redirect"],
};

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
function jwtNone(kid, role = "admin") {
  return `${b64u({ alg: "none", typ: "JWT", kid })}.${b64u({ sub: "patt", role, exp: 9999999999 })}.`;
}

let n = 0, seq = 0;
for (const e of PATT_CATALOG) {
  assertPatt({ id: e.id, template: e.template, source: e.source });
  const vuln = e.vuln;
  const canary = `nxp${String(seq++).padStart(4, "0")}`;
  const payload = withCanary(e.template, canary);

  const mkMatchers = () => {
    const m = e.match || { kind: "word" };
    if (m.kind === "time") return [{ type: "time", ms: m.ms || 2500 }];
    if (m.kind === "regex") return [{ type: "regex", part: "body", regex: m.regex }];
    if (m.kind === "word-headers") return [{ type: "word", part: "headers", words: m.words }];
    if (m.kind === "word" && m.words) return [{ type: "word", part: "body", words: m.words }];


    return [{ type: "word", part: "body", words: [canary] }];
  };

  const desc = `${e.note} [patt:${e.id}] [patt_source:${e.source}]`;
  const baseTags = [vuln, "patt"];

  const TECH_REQUIRE = ["php", "wordpress", "laravel", "java", "dotnet", "django", "python", "node", "ruby", "graphql"];
  const requires = (e.techs || []).filter((t) => TECH_REQUIRE.includes(String(t).toLowerCase()));

  if (vuln === "nosql") {
    const body = payload.startsWith("{") ? payload : JSON.stringify({ username: { $ne: null }, password: { $ne: null } });
    write(`${e.id}-login`, {
      name: `PATT NoSQL ${e.id}`, severity: e.severity, type: "active", tags: [...baseTags, "injection", "api"],
      description: desc, requires,
      requests: [{ method: "POST", path: "{{BaseURL}}/api/login", sendHeaders: { "Content-Type": "application/json" }, body, matchers: mkMatchers() }],
    });
    n++;
    continue;
  }
  if (vuln === "jwt") {
    const tok = jwtNone(`k-${canary}`, "admin");
    write(`${e.id}-${canary}`, {
      name: `PATT JWT none kid k-${canary}`, severity: e.severity, type: "active", tags: [...baseTags, "auth", "none"],
      description: `${desc} [teknik:${payload}]`,
      requests: [{ method: "GET", path: "{{BaseURL}}/api/profile", sendHeaders: { Authorization: `Bearer ${tok}` }, matchAll: true, matchers: [{ type: "status", status: [200] }, { type: "word", part: "body", words: ["admin"] }] }],
    });
    n++;
    continue;
  }
  if (vuln === "graphql") {
    for (const param of ["query", "q"]) {
      write(`${e.id}-${param}`, {
        name: `PATT GraphQL ${e.id} via ${param}`, severity: e.severity, type: "active", tags: [...baseTags, "api", "introspection"],
        description: desc, requires: ["graphql"],
        requests: [{ method: "GET", path: "{{BaseURL}}", payloads: { [param]: [payload] }, matchers: mkMatchers() }],
      });
      n++;
    }
    continue;
  }
  if (vuln === "cors") {
    const origin = payload.includes("null") ? "null" : "https://evil.example";
    write(`${e.id}`, {
      name: `PATT CORS ${e.id}`, severity: e.severity, type: "active", tags: [...baseTags, "headers", "api"],
      description: desc,
      requests: [{ method: "GET", path: "{{BaseURL}}/api/data", sendHeaders: { Origin: origin }, matchers: mkMatchers() }],
    });
    n++;
    continue;
  }

  const params = PARAMS[vuln] || ["q"];
  for (const param of params) {
    const tid = `${e.id}-${param}`;
    const extraTag = e.bypasses?.[0] ? [String(e.bypasses[0]).replace(/[^a-z0-9]+/gi, "").toLowerCase().slice(0, 24)] : [];
    write(tid, {
      name: `PATT ${vuln} ${e.id} via ${param}`, severity: e.severity, type: "active",
      tags: [...baseTags, ...extraTag].filter(Boolean),
      description: desc, requires,
      requests: [{ method: "GET", path: "{{BaseURL}}", payloads: { [param]: [payload] }, matchers: mkMatchers() }],
    });
    n++;
  }
}

console.log(`patt generated ${n} templates -> templates/patt/`);
console.log(`filter: --tags patt / --tags patt,xss / --tags patt,sqli ...`);
