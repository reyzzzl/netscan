// TODO: cap stored retest count
// FIXME: baseline doubles slow scans
import { tracedFetch } from "./http.js";
import { evalMatchers } from "./match.js";
import { renderPath } from "./templates.js";
import { mappingFor } from "./mapping.js";
import { PROBES, detectProbe } from "./probe.js";
import { crawlRecursive } from "./crawl.js";
import { baselineUrl, echoFreeHit, effectiveMatchers, isStatusOnly, judgeXss, reflectionGap } from "./validate.js";
import { logFinding } from "./store.js";
import { findingScore, targetScore } from "./score.js";
import { c } from "./util.js";

async function pool(items, n, fn, onProgress) {
  const ret = [];
  let idx = 0, done = 0;
  const workers = Array.from({ length: Math.max(1, n) }, async () => {
    while (idx < items.length) {
      const cur = idx++;
      ret[cur] = await fn(items[cur], cur);
      done++;
      if (onProgress && done % 50 === 0) onProgress(done, items.length);
    }
  });
  await Promise.all(workers);
  return ret;
}


function pageParams(url, body) {
  const set = new Set();
  try { for (const k of new URL(url).searchParams.keys()) set.add(k); } catch {}
  const html = String(body || "").slice(0, 50000);
  for (const m of html.matchAll(/name\s*=\s*["']?([a-zA-Z][a-zA-Z0-9_\-:]{0,40})/g)) {
    if (set.size >= 25) break;
    set.add(m[1]);
  }
  for (const m of html.matchAll(/[?&]([a-zA-Z][a-zA-Z0-9_]{0,40})=/g)) {
    if (set.size >= 25) break;
    set.add(m[1]);
  }
  return [...set].slice(0, 25);
}

function ownParams(req) {
  return Object.keys(req.payloads || {});
}

function flatPayloads(req) {
  const out = [];
  for (const v of Object.values(req.payloads || {})) {
    const a = Array.isArray(v) ? v : [v];
    for (const p of a) if (!out.includes(p)) out.push(p);
  }
  return out;
}

function fingerprint(pages) {
  const hay = pages.map((p) => JSON.stringify(p.resHeaders || p.headers || {}) + "\n" + String(p._body || p.body || "").slice(0, 20000)).join("\n").toLowerCase();
  const techs = new Set();
  if (/php|phpse?ssid|\.php/.test(hay)) techs.add("php");
  if (/wp-content|wordpress/.test(hay)) techs.add("wordpress");
  if (/jsessionid|\.jsp|spring|tomcat|jboss|weblogic/.test(hay)) techs.add("java");
  if (/asp\.net|__viewstate|__eventvalidation|iis/.test(hay)) techs.add("dotnet");
  if (/django|csrfmiddlewaretoken/.test(hay)) techs.add("django");
  if (/laravel|laravel_session/.test(hay)) techs.add("laravel");
  if (/express|connect\.sid/.test(hay)) techs.add("node");
  if (/rails|_rails|ruby/.test(hay)) techs.add("ruby");
  if (/flask|fastapi|jinja|werkzeug/.test(hay)) techs.add("python");
  if (/graphql|__schema/.test(hay)) techs.add("graphql");
  if (/drupal/.test(hay)) techs.add("drupal");
  if (/joomla/.test(hay)) techs.add("joomla");
  return techs;
}

export async function runScan({ baseUrl, templates, threads = 20, crawlDepth = 1, crawlLimit = 20, trace = true, includeIds = [], excludeIds = [], severity = [], tags = [], maxRequests = 20000, noGate = false, noVerify = false, maxPerTemplate = 200, recursive = false, validOnly = true, showAll = false }) {
  validOnly = showAll ? false : validOnly;
  let temps = templates;
  if (includeIds.length) {
    const set = new Set(includeIds.map((s) => String(s).toLowerCase()));
    temps = temps.filter((t) => set.has(String(t.id).toLowerCase()));
  }
  if (excludeIds.length) {
    const subs = excludeIds.map((s) => String(s).toLowerCase());
    const before = temps.length;
    temps = temps.filter((t) => !subs.some((sub) => String(t.id).toLowerCase().includes(sub)));
    console.log(c("dim", `  exclude: ${before - temps.length} dropped (${subs.join(",")})`));
  }
  if (severity.length) {
    const set = new Set(severity.map((s) => String(s).toLowerCase()));
    temps = temps.filter((t) => set.has(String(t.severity).toLowerCase()));
  }
  if (tags.length) {
    const set = new Set(tags.map((s) => String(s).toLowerCase()));
    temps = temps.filter((t) => (t.tags || []).some((x) => set.has(x)));
  }

  const print = (m, url, st, ms, tid) => {
    if (!trace) return;
    const col = st >= 500 ? "red" : st >= 400 ? "yellow" : st === 0 ? "red" : "green";
    console.log(`${c("dim", new Date().toISOString().slice(11, 19))} ${c("cyan", m)} ${(url || "").slice(0, 110)} ${c(col, st)} ${ms}ms ${c("dim", tid || "")}`);
  };

  const baseNoSlash = baseUrl.replace(/\/+$/, "");
  const rawDepth = crawlDepth === true ? 1 : Number(crawlDepth);
  const depth = recursive ? Math.max(Number.isFinite(rawDepth) ? rawDepth : 1, 3) : (Number.isFinite(rawDepth) ? rawDepth : 1);
  console.log(c("cyan", `▸ base ${baseUrl} | ${temps.length} templates | threads ${threads} | crawl depth-${depth}${recursive ? " (deep)" : ""} | maxReq ${maxRequests} | gate ${noGate ? "off" : "on"} | verify ${noVerify ? "off" : "on"} | ${validOnly ? "valid-only" : "all"}`));

  const base = await tracedFetch(baseUrl, { template: "base" });
  print("GET", baseUrl, base.status, base.ms, "base");
  const fetched = new Map([[baseUrl, base]]);
  const fetchCached = async (u) => {
    if (fetched.has(u)) return fetched.get(u);
    const r = await tracedFetch(u, { template: "crawl" });
    print("GET", u, r.status, r.ms, "crawl");
    fetched.set(u, r);
    return r;
  };
  let targets = [baseUrl];
  if (depth > 0 && base.body) {
    targets = await crawlRecursive(baseUrl, { depth, limit: crawlLimit, fetchFn: fetchCached });
    console.log(c("dim", `  crawl: +${targets.length - 1} same-host urls depth-${depth} (${targets.length} used)`));
  }

  let wildcard200 = false;
  try {
    const probe404 = await tracedFetch(`${baseNoSlash}/.netscan-${Date.now().toString(36)}-404/`, { template: "wildcard" });
    wildcard200 = probe404.status === 200;
    if (wildcard200) console.log(c("yellow", "  wildcard-200: random path also 200, status-only hidden"));
  } catch {}

  const pages = [];
  for (const u of targets) {
    const r = u === baseUrl ? base : await fetchCached(u);
    pages.push({ url: u, ...r });
  }
  for (const pg of pages) pg.params = pageParams(pg.url, pg._body || pg.body);


  const techs = fingerprint(pages);
  if (techs.size) {
    const before = temps.length;
    temps = temps.filter((t) => {
      const req = (t.requires || []).map((s) => String(s).toLowerCase());
      if (!req.length) return true;
      return req.some((r) => techs.has(r));
    });
    console.log(c("dim", `  tech: ${[...techs].join(",") || "-"} | templates ${before} -> ${temps.length}`));
  }

  const findings = [];
  const passive = temps.filter((t) => t.type === "passive");
  const active = temps.filter((t) => t.type !== "passive" && t.type !== "stored");
  const stored = temps.filter((t) => t.type === "stored");

  for (const t of passive) {
    for (const p of pages) {
      const matchAll = t["match-all"] === true;
      if (evalMatchers(p, t.matchers || [], matchAll)) {
        const f = finish(t, p.url, p.traceId, null, t.description || "passive match", "passive");
        f.valid = true; f.confidence = "medium";
        findings.push(f); logFinding(f);
        console.log(`  ${sevTag(t.severity)} ${t.id} ${c("dim", "@ " + p.url.slice(0, 90))}`);
      }
    }
  }

  const targetSlice = targets;
  const pageByUrl = new Map(pages.map((p) => [p.url, p]));


  const openGates = {};
  const gatedFams = [...new Set(active.filter((t) => PROBES[(t.tags || [])[0]] && (t.requests || []).every((r) => String(r.path || "{{BaseURL}}").trim() === "{{BaseURL}}")).map((t) => t.tags[0]))];
  if (!noGate && gatedFams.length) {
    const probes = [];
    for (const fam of gatedFams) {
      const def = PROBES[fam];
      for (const target of targetSlice) {
        const pg = pageByUrl.get(target);
        if (pg && detectProbe({ status: pg.status, headers: pg.headers, body: pg._body || pg.body }, def.matchers)) continue;
        const params = (pg && pg.params.length ? pg.params : def.fallback).slice(0, 8);
        for (const param of params) {
          for (const pay of (def.payloads ? def.payloads() : [def.payload()])) {
            probes.push({ fam, target, param, pay, matchers: def.matchers });
          }
        }
      }
    }
    await pool(probes, threads, async (pb) => {
      let u;
      try {
        u = new URL(pb.target);
        setPayloadParam(u, pb.param, pb.pay);
      } catch { return; }
      const r = await tracedFetch(u.toString(), { template: "probe" });
      if (detectProbe(r, pb.matchers)) {
        openGates[pb.fam] = openGates[pb.fam] || new Map();
        if (!openGates[pb.fam].has(pb.target)) openGates[pb.fam].set(pb.target, new Set());
        openGates[pb.fam].get(pb.target).add(pb.param);
      }
    });
    for (const fam of gatedFams) {
      const n = [...(openGates[fam] || new Map()).values()].reduce((a, s) => a + s.size, 0);
      console.log(c("dim", `  gate ${fam}: ${n} sink terbuka`));
    }
  }


  const seen = new Set();
  const jobs = [];
  let gatedOut = 0;
  const pushJob = (t, req, url, ctx) => {
    if (jobs.length >= maxRequests) return false;
    const hdrBody = JSON.stringify({ h: req.sendHeaders || {}, b: req.body || null });
    const key = `${req.method || "GET"} ${url} ${hdrBody}`;
    if (seen.has(key)) return true;
    seen.add(key);
    jobs.push(mkJob(t, req, url, ctx));
    return true;
  };

  for (const t of active) {
    const fam = (t.tags || [])[0];
    const gated = !noGate && PROBES[fam];
    let perT = 0;
    for (const req of t.requests || []) {
      const paths = Array.isArray(req.paths) ? req.paths : [req.path || "{{BaseURL}}"];
      const generic = paths.length === 1 && String(paths[0]).trim() === "{{BaseURL}}";
      const payloads = flatPayloads(req);
      const own = ownParams(req);
      for (const target of targetSlice) {
        const pg = pageByUrl.get(target);
        let params;
        if (generic && gated) {
          const open = openGates[fam] && openGates[fam].get(target);
          if (!open || !open.size) { gatedOut++; continue; }
          params = [...open];
        } else if (generic) {
          params = (pg && pg.params.length ? pg.params : own);
        } else {
          params = [null];
        }
        for (const p of paths) {
          if (!generic) {
            const own = ownParams(req);
            if (!own.length) {
              const url = resolveUrl(p, target, baseUrl, {});
              if (perT++ >= maxPerTemplate) break;
              if (!pushJob(t, req, url, { BaseURL: baseNoSlash, Host: hostOf(baseUrl) })) break;
            } else {
              for (const pk of own) {
                for (const pay of (Array.isArray(req.payloads[pk]) ? req.payloads[pk] : [req.payloads[pk]])) {
                  const ctx = { BaseURL: baseNoSlash, Host: hostOf(baseUrl), payload: pay, param: pk };
                  const url = resolveUrl(p, target, baseUrl, ctx, pk, pay);
                  if (perT++ >= maxPerTemplate) break;
                  if (!pushJob(t, req, url, ctx)) break;
                }
                if (perT >= maxPerTemplate || jobs.length >= maxRequests) break;
              }
            }
          } else if (!payloads.length) {
            const url = resolveUrl(p, target, baseUrl, {});
            if (perT++ >= maxPerTemplate) break;
            if (!pushJob(t, req, url, { BaseURL: baseNoSlash, Host: hostOf(baseUrl) })) break;
          } else {
            for (const pk of params) {
              if (pk === null) continue;
              for (const pay of payloads) {
                const ctx = { BaseURL: baseNoSlash, Host: hostOf(baseUrl), payload: pay, param: pk };
                const url = resolveUrl(p, target, baseUrl, ctx, pk, pay);
                if (perT++ >= maxPerTemplate) break;
                if (!pushJob(t, req, url, ctx)) break;
              }
              if (perT >= maxPerTemplate || jobs.length >= maxRequests) break;
            }
          }
          if (perT >= maxPerTemplate || jobs.length >= maxRequests) break;
        }
        if (perT >= maxPerTemplate || jobs.length >= maxRequests) break;
      }
      if (perT >= maxPerTemplate || jobs.length >= maxRequests) break;
    }
    if (jobs.length >= maxRequests) break;
  }

  console.log(c("dim", `  active jobs: ${jobs.length}${jobs.length >= maxRequests ? " (capped by --max-requests)" : ""}${gatedOut ? ` | gate-skip ${gatedOut}` : ""}`));
  let unverified = 0;
  const dropped = { static: 0, context: 0, wildcard: 0 };
  const drop = (reason, j, url, traceId, detail) => {
    dropped[reason]++;
    if (!showAll) return;
    const matchers = effectiveMatchers(j.req, j.t);
    const f = finish(j.t, url, traceId, j.method, `candidate (${detail})`, "active", false);
    f.candidate = true; f.valid = false; f.reason = detail;
    if (j.ctx && j.ctx.param) f.param = j.ctx.param;
    findings.push(f); logFinding(f);
    console.log(`  ${c("dim", "[candidate:" + detail + "]")} ${j.t.id} ${c("dim", "@ " + url.slice(0, 100))}`);
  };
  const matchAllFor = (req, t) => (req["match-all"] ?? t["match-all"]) === true;
  await pool(jobs, threads, async (j) => {
    const url = renderPath(j.target, j.ctx || {});
    const headers = { ...(j.req.headers || {}) };
    if (j.req.sendHeaders) Object.assign(headers, j.req.sendHeaders);
    const fetchOpts = { method: j.method, headers, body: j.body, template: j.t.id };
    let r = await tracedFetch(url, fetchOpts);
    if (r.status === 0 && r.error) r = await tracedFetch(url, fetchOpts);
    print(j.method, url, r.status, r.ms, j.t.id);
    if (!checkHit(r, j.req, j.t)) return;
    if (!noVerify) {
      const r2 = await tracedFetch(url, fetchOpts);
      if (!checkHit(r2, j.req, j.t)) { unverified++; return; }
    }
    const matchers = effectiveMatchers(j.req, j.t);
    const matchAll = matchAllFor(j.req, j.t);
    const fam0 = ((j.t.tags || [])[0] || "").toLowerCase();
    const param = (j.ctx && j.ctx.param) || null;
    if (validOnly && isStatusOnly(matchers) && !param && wildcard200) {
      drop("wildcard", j, url, r.traceId, "status-only di server wildcard-200");
      return;
    }
    let exploit = null;
    if (validOnly && param) {
      const bUrl = baselineUrl(url, param);
      if (bUrl) {
        const rb = await tracedFetch(bUrl, { ...fetchOpts, template: "baseline" });
        const nonTime = matchers.filter((m) => String(m.type || "").toLowerCase() !== "time");
        const tNeed = matchers.find((m) => String(m.type || "").toLowerCase() === "time");
        const baseHit = nonTime.length ? evalMatchers(rb, nonTime, matchAll) : false;
        const baseSlow = tNeed ? rb.ms >= Number(tNeed.ms || 5000) : false;
        if (baseHit || baseSlow) {
          drop("static", j, url, r.traceId, "baseline also matches (static content)");
          return;
        }
        const sent = (j.ctx && j.ctx.payload) || "";
        if (!["xss", "stored"].includes(fam0)) {
          if (!echoFreeHit(r, matchers, matchAll, sent)) {
            drop("static", j, url, r.traceId, "payload echo only, no server content");
            return;
          }
        } else {
          const gap = reflectionGap(r.body, rb.body);
          const verdict = judgeXss(r.body, matchers, gap);
          if (!verdict.ok) {
            drop("context", j, url, r.traceId, verdict.reason);
            return;
          }
          exploit = { rating: verdict.rating, context: verdict.context, snippet: verdict.snippet };
        }
      } else if (["xss", "stored"].includes(fam0)) {
        const verdict = judgeXss(r.body, matchers);
        if (!verdict.ok) {
          drop("context", j, url, r.traceId, verdict.reason);
          return;
        }
        exploit = { rating: verdict.rating, context: verdict.context, snippet: verdict.snippet };
      }
    } else if (["xss", "stored"].includes(fam0)) {
      const verdict = judgeXss(r.body, matchers);
      if (!verdict.ok) {
        if (validOnly) {
          drop("context", j, url, r.traceId, verdict.reason);
          return;
        }
      } else {
        exploit = { rating: verdict.rating, context: verdict.context, snippet: verdict.snippet };
      }
    } else if (validOnly && !param && (j.body || j.req.sendHeaders)) {
      const rb = await tracedFetch(url, { method: "GET", headers: {}, body: null, template: "baseline" });
      const nonTime = matchers.filter((m) => String(m.type || "").toLowerCase() !== "time");
      if (nonTime.length && evalMatchers(rb, nonTime, matchAll)) {
        drop("static", j, url, r.traceId, "baseline also matches (static content)");
        return;
      }
    }
    const f = finish(j.t, url, r.traceId, j.method, `matched ${matchers.map((m) => m.type).join(",")}`, "active", true);
    f.valid = true;
    f.confidence = isStatusOnly(matchers) && !param ? "medium" : "high";
    if (param) f.param = param;
    if (exploit) f.exploit = exploit;
    findings.push(f); logFinding(f);
    console.log(`  ${sevTag(j.t.severity)} ${j.t.id} ${c("dim", "@ " + url.slice(0, 100))} ${c("dim", "trace:" + String(r.traceId).slice(0, 13))}`);
  }, (d, total) => { if (trace) console.log(c("dim", `  ... ${d}/${total}`)); });
  if (unverified) console.log(c("dim", `  unverified dropped: ${unverified}`));
  const nDrop = dropped.static + dropped.context + dropped.wildcard;
  if (validOnly && nDrop) console.log(c("dim", `  hidden candidates: ${nDrop} (static:${dropped.static} xss-context:${dropped.context} wildcard:${dropped.wildcard}) — use --show-all`));


  if (stored.length) {
    console.log(c("dim", `  stored templates: ${stored.length}`));
    for (const t of stored) {
      const steps = t.requests || [];
      if (steps.length < 2) continue;
      const ctx = { BaseURL: baseNoSlash, Host: hostOf(baseUrl) };
      const s0 = steps[0];
      const url0 = renderPath(s0.path || "{{BaseURL}}", ctx);
      const h0 = { ...(s0.headers || {}), ...(s0.sendHeaders || {}) };
      const r0 = await tracedFetch(url0, { method: s0.method || "POST", headers: h0, body: s0.body || null, template: t.id });
      print(s0.method || "POST", url0, r0.status, r0.ms, t.id + ":store");
      const s1 = steps[1];
      const url1 = renderPath(s1.path || "{{BaseURL}}", ctx);
      const h1 = { ...(s1.headers || {}), ...(s1.sendHeaders || {}) };
      const r1 = await tracedFetch(url1, { method: s1.method || "GET", headers: h1, body: s1.body || null, template: t.id });
      print(s1.method || "GET", url1, r1.status, r1.ms, t.id + ":read");
      const matchers = s1.matchers || t.matchers || [];
      if (matchers.length && evalMatchers(r1, matchers.filter((m) => m.type !== "time"), (s1["match-all"] ?? t["match-all"]) === true)) {
        const f = finish(t, url1, r1.traceId, s1.method || "GET", `stored canary via ${url0.slice(0, 80)}`, "active", true);
        f.valid = true; f.confidence = "high";
        findings.push(f); logFinding(f);
        console.log(`  ${sevTag(t.severity)} ${t.id} ${c("dim", "@ " + url1.slice(0, 100))} ${c("dim", "trace:" + String(r1.traceId).slice(0, 13))}`);
      }
    }
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  const valid = findings.filter((f) => !f.candidate);
  const nCand = findings.length - valid.length;
  console.log(c("bold", `\nResults: ${valid.length} valid${nCand ? ` (+${nCand} candidates)` : ""} (${jobs.length} active req + ${pages.length} passive pages + ${stored.length} stored)`));
  const sinks = sinkSummary(valid);
  console.log(c("bold", `Unique vulns (per sink): ${sinks.length}`));
  for (const sk of sinks.slice(0, 30)) {
    console.log(`  ${sevTag(sk.sev)} ${sk.cat} ${sk.path}${sk.param ? " [" + sk.param + "]" : ""} ${c("dim", `x${sk.n} ex:${sk.ex} verified:${sk.verified}/${sk.n}`)}`);
  }
  if (sinks.length > 30) console.log(c("dim", `  ... +${sinks.length - 30} more sinks (see report)`));
  if (!valid.length) console.log(c("green", "  Clean for these templates (not proof of safety)."));
  const agg = targetScore(valid);
  console.log(c("bold", `\nTarget score: ${agg.score}/100 (grade ${agg.grade})  C:${agg.counts.critical} H:${agg.counts.high} M:${agg.counts.medium} L:${agg.counts.low} unique:${agg.counts.uniqueTemplates}`));
  const top = Object.entries(agg.byCat).sort((a, b) => ((b[1].critical * 15 + b[1].high * 7 + b[1].medium * 3 + b[1].low) - (a[1].critical * 15 + a[1].high * 7 + a[1].medium * 3 + a[1].low))).slice(0, 8);
  for (const [cat, v] of top) console.log(`  ${c("cyan", cat)} C:${v.critical} H:${v.high} M:${v.medium} L:${v.low} I:${v.info || 0}`);
  console.log(c("dim", "  Trace: netscan history / netscan show <traceId> | summary: netscan report"));
  return findings;
}

function checkHit(r, req, t) {
  const matchers = req.matchers || t.matchers || [];
  const nonTime = matchers.filter((m) => m.type !== "time");
  let hit = nonTime.length ? evalMatchers(r, nonTime, (req["match-all"] ?? t["match-all"]) === true) : false;
  const tNeed = matchers.find((m) => m.type === "time");
  if (tNeed && r.ms >= Number(tNeed.ms || 5000)) hit = true;
  return hit;
}

function pattOf(t) {
  const d = String((t && t.description) || "");
  const id = (/\[patt:([^\]]+)\]/.exec(d) || [])[1] || null;
  const src = (/\[patt_source:([^\]]+)\]/.exec(d) || [])[1] || null;
  return { id, src };
}

function finish(t, url, traceId, method, evidence, type, verified = false) {
  const f = {
    template: t.id, name: t.name || t.id, severity: t.severity,
    tags: t.tags || [], mapping: t.mapping || mappingFor(t.tags || []),
    type, url, traceId, evidence: String(evidence).slice(0, 300),
  };
  const p = pattOf(t);
  if (p.id) f.patt = p.id;
  if (p.src) f.patt_source = p.src;
  if (method) f.method = method;
  if (verified) f.verified = true;
  f.score = findingScore({ ...f, verified });
  return f;
}

export function sinkKey(f) {
  let path = "", param = f.param || "";
  try { path = new URL(f.url).pathname || "/"; } catch { path = String(f.url || "").split("?")[0]; }
  const cat = ((f.mapping && f.mapping.tag) || (f.tags || [])[0] || "misc").toLowerCase();
  return `${cat}|${path}|${param}`;
}

export function sinkSummary(findings) {
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const g = new Map();
  for (const f of findings) {
    const k = sinkKey(f);
    if (!g.has(k)) {
      let path = "";
      try { path = new URL(f.url).pathname || "/"; } catch { path = String(f.url || "").split("?")[0]; }
      g.set(k, { key: k, cat: ((f.mapping && f.mapping.tag) || (f.tags || [])[0] || "misc"), path, param: f.param || "", n: 0, verified: 0, sev: f.severity, ex: f.template });
    }
    const e = g.get(k);
    e.n++;
    if (f.verified) e.verified++;
    if ((order[f.severity] ?? 9) < (order[e.sev] ?? 9)) { e.sev = f.severity; e.ex = f.template; }
  }
  return [...g.values()].sort((a, b) => ((order[a.sev] ?? 9) - (order[b.sev] ?? 9)) || (b.n - a.n));
}

function mkJob(t, req, url, ctx = { BaseURL: "", Host: "", payload: "", param: "" }) {
  return { t, req, target: url, ctx, body: req.body || null, method: req.method || "GET" };
}

function resolveUrl(p, target, baseUrl, ctx, pk = null, pay = null) {
  const baseNoSlash = String(baseUrl || "").replace(/\/+$/, "");
  const trimmed = String(p).trim();
  if (trimmed === "{{BaseURL}}") {
    try {
      const u = new URL(target);
      if (pk && pay !== null) setPayloadParam(u, pk, pay);
      return u.toString();
    } catch {  }
  }
  let rendered = renderPath(p, { BaseURL: baseNoSlash, Host: hostOf(baseUrl), ...(ctx || {}) });
  try {
    const u = new URL(rendered, target);
    if (p.startsWith("/") && !p.startsWith("{{")) {
      const t = new URL(target);
      return new URL(rendered, `${t.protocol}//${t.host}`).toString();
    }
    if (pk && pay !== null) setPayloadParam(u, pk, pay);
    return u.toString();
  } catch { return rendered; }
}

function setPayloadParam(u, pk, pay) {
  if (/%[0-9A-Fa-f]{2}/.test(pay)) {
    u.searchParams.delete(pk);
    const sep = u.search ? "&" : "?";
    u.search += `${sep}${encodeURIComponent(pk)}=${String(pay).replace(/ /g, "+")}`;
  } else {
    u.searchParams.set(pk, pay);
  }
}

function hostOf(u) { try { return new URL(u).host; } catch { return ""; } }

function sevTag(s) {
  const col = s === "critical" || s === "high" ? "red" : s === "medium" ? "yellow" : "dim";
  return c(col, `[${String(s || "info").toUpperCase()}]`);
}
