// TODO: cache parsed templates
// FIXME: dup ids overwrite silently
import fs from "node:fs";
import path from "node:path";
import { parseSimpleYaml } from "./yaml.js";
import { mappingFor } from "./mapping.js";

export function loadTemplates(dir) {
  const files = collectYaml(dir);
  const out = [];
  for (const f of files) {
    try {
      const raw = fs.readFileSync(f, "utf8");
      const t = parseSimpleYaml(raw);
      t._file = path.relative(dir, f);
      t.mapping = t.mapping || mappingFor(t.tags);
      t.requires = normList(t.requires);
      t.id = t.id || path.basename(f).replace(/\.(yaml|yml)$/, "");
      t.severity = String(t.severity || "info").toLowerCase();
      t.type = String(t.type || "active").toLowerCase();
      t.tags = normList(t.tags);
      t.requests = Array.isArray(t.requests) ? t.requests : [];

      if (t.matchers && !Array.isArray(t.matchers)) t.matchers = [t.matchers];
      for (const r of t.requests) {
        if (r.matchers && !Array.isArray(r.matchers)) r.matchers = [r.matchers];

        if (r.payloads && typeof r.payloads === "object" && !Array.isArray(r.payloads)) {
          for (const k of Object.keys(r.payloads)) {
            if (!Array.isArray(r.payloads[k])) r.payloads[k] = [r.payloads[k]];
          }
        }
      }
      out.push(t);
    } catch (e) { console.error(`bad template: ${f}: ${e.message}`); }
  }
  out.sort((a, b) => a.id.localeCompare(b.id));
  return out;
}

function collectYaml(dir, acc = []) {
  let ents = [];
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return acc; }
  for (const e of ents) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) collectYaml(p, acc);
    else if (e.name.endsWith(".yaml") || e.name.endsWith(".yml")) acc.push(p);
  }
  return acc;
}

function normList(v) {
  if (v === undefined) return [];
  const a = Array.isArray(v) ? v.flat() : String(v).split(",").map((s) => s.trim());
  return a.map((s) => String(s).toLowerCase()).filter(Boolean);
}


export function renderPath(tpl, ctx) {
  let s = String(tpl);
  for (const [k, v] of Object.entries(ctx)) s = s.split(`{{${k}}}`).join(String(v));
  return s;
}
