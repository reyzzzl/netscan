#!/usr/bin/env node
// TODO: add json output flag
// FIXME: HEAD probe hides soft 404
import path from "node:path";
import { parseArgs, arr, c } from "./util.js";
import { loadTemplates } from "./templates.js";
import { runScan, sinkSummary } from "./engine.js";
import { listTraces, getTrace, listFindings, clearAll } from "./store.js";
import { targetScore } from "./score.js";

function help() {
  console.log(`
${c("bold", "netscan")} - template scanner + network trace (zero-dep)
Authorized targets only.

  scan       run scan   ex: netscan scan --url http://127.0.0.1:8081/ --tags xss,sqli
  fast       alias: netscan TARGET [--tags ..]  ex: netscan demo.testfire.net
  templates  list templates   ex: netscan templates --tags xss
  history    request log   ex: netscan history --limit 20
  show       one trace   ex: netscan show <traceId>
  findings   valid findings   ex: netscan findings --limit 20
  report     score + summary   ex: netscan report
  clear      wipe history+findings

Scan opts: --url/-u (required), --templates (dir, default ./templates),
  --fast (preset: threads 15, max-requests 3000, crawl 15, per-template 60),
  --threads/-t (default 20), --crawl N (depth, default 1; 0 = off),
  --recursive (deep crawl: min depth 3), --crawl-limit (max pages, default 20),
  --id (repeatable), --exclude-id stacked,time (repeatable), --severity high,medium, --tags xss,sqli,ssrf,
  --max-requests (default 20000), --no-trace, --no-gate,
  --no-verify, --max-per-template (default 200), --insecure/-k,
  --show-all (include candidates; default valid only), --no-valid-only (disable filter)
`.trim());
}

const COMMANDS = ["scan", "templates", "history", "show", "findings", "report", "clear", "help"];
function looksLikeTarget(s) {
  return /^(https?:\/\/)?[a-z0-9.-]+\.[a-z]{2,}(:\d+)?(\/.*)?$/i.test(s) && !s.includes(" ");
}

function crawlDepthOf(args) {
  const raw = args.crawl ?? args["max-depth"];
  if (raw === true || raw === undefined || raw === false) return 1;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : 1;
}

async function fastScan(url, args) {
  if (args.insecure || args.k) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    console.log(c("dim", "  --insecure: TLS verify off"));
  }
  const dir = args.templates || path.join(process.cwd(), "templates");
  const { loadTemplates } = await import("./templates.js");
  const templates = loadTemplates(dir);
  if (!templates.length) throw new Error(`no templates in ${dir}`);
  let target = url;
  try {
    const r = await fetch(target, { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(10000) });
    console.log(c("dim", `  target ${r.status} (HEAD)`));
  } catch (e) {
    if (!args.insecure && !args.k) {
      console.log(c("yellow", "  TLS/HEAD failed, retrying --insecure..."));
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    } else throw new Error("target unreachable: " + e.message);
  }
  await runScan({
    baseUrl: target,
    templates,
    threads: parseInt(args.threads || args.t || "15", 10),
    crawlDepth: crawlDepthOf(args),
    crawlLimit: parseInt(args["crawl-limit"] || (args.recursive ? "50" : "15"), 10),
    trace: !args["no-trace"],
    includeIds: arr(args.id),
    severity: splitTags(arr(args.severity)),
    tags: splitTags(arr(args.tags)),
    maxRequests: parseInt(args["max-requests"] || args.m || "3000", 10),
    noGate: !!args["no-gate"],
    noVerify: false,
    maxPerTemplate: parseInt(args["max-per-template"] || "60", 10),
    recursive: !!args.recursive,
    validOnly: !args["show-all"] && !args["no-valid-only"],
    showAll: !!args["show-all"],
  });
}

async function main() {
  const args = parseArgs(process.argv);
  let [cmd, ...rest] = args._;
  if (cmd && !COMMANDS.includes(cmd) && looksLikeTarget(cmd) && !args.help && !args.h) {

    let target = cmd;
    if (!/^https?:\/\//i.test(target)) target = "https://" + target;
    return await fastScan(target, args);
  }
  if (!cmd || cmd === "help" || args.help || args.h) return help();

  if (cmd === "templates") {
    const dir = args.templates || "./templates";
    const ts = loadTemplates(dir);
    const tagF = splitTags(arr(args.tags));
    const list = tagF.length ? ts.filter((t) => (t.tags || []).some((x) => tagF.includes(x))) : ts;
    if (!list.length) return console.log(c("dim", `(empty in ${dir})`));
    const byType = {};
    for (const t of list) {
      const k = `${t.type}/${(t.tags || [])[0] || "misc"}`;
      byType[k] = (byType[k] || 0) + 1;
    }
    console.log(c("bold", `${list.length} templates (${ts.length} total)`));
    for (const [k, v] of Object.entries(byType).sort()) console.log(`  ${c("cyan", k)}: ${v}`);
    if (args.verbose || args.v) {
      for (const t of list.slice(0, 100)) {
        const mCount = (t.matchers || []).length + (t.requests || []).reduce((a, r) => a + ((r.matchers || []).length), 0);
        console.log(`${c("cyan", t.id)} [${t.severity}/${t.type}] ${(t.name || "").slice(0, 70)} ${c("dim", `(${(t.requests || []).length} req, ${mCount} matcher) ${t._file}`)}`);
      }
      if (list.length > 100) console.log(c("dim", `  ... +${list.length - 100} (use --tags)`));
    } else {
      console.log(c("dim", "  add --verbose to list, --tags to filter"));
    }
    return;
  }
  if (cmd === "scan" && args.fast) {
    const url = args.url || args.u || rest[0];
    if (!url) throw new Error("need --url. ex: netscan scan --url http://127.0.0.1:8081/ [--fast]");
    try { new URL(url); } catch { throw new Error("bad --url: " + url); }
    return await fastScan(url, args);
  }
  if (cmd === "scan") {
    const url = args.url || args.u;
    if (!url) throw new Error("need --url. ex: netscan scan --url http://127.0.0.1:8081/");
    try { new URL(url); } catch { throw new Error("bad --url: " + url); }
    const dir = args.templates || path.join(process.cwd(), "templates");
    if (args.insecure || args.k) {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
      console.log(c("dim", "  --insecure: TLS verify off"));
    }
    const templates = loadTemplates(dir);
    if (!templates.length) throw new Error(`no templates in ${dir}`);
    await runScan({
      baseUrl: url,
      templates,
      threads: parseInt(args.threads || args.t || "20", 10),
      crawlDepth: crawlDepthOf(args),
      crawlLimit: parseInt(args["crawl-limit"] || (args.recursive ? "50" : "20"), 10),
      trace: !args["no-trace"],
      includeIds: arr(args.id),
      excludeIds: [...arr(args.exclude), ...arr(args["exclude-id"])],
      severity: splitTags(arr(args.severity)),
      tags: splitTags(arr(args.tags)),
      maxRequests: parseInt(args["max-requests"] || args.m || "20000", 10),
      noGate: !!args["no-gate"],
      noVerify: !!args["no-verify"],
      maxPerTemplate: parseInt(args["max-per-template"] || "200", 10),
      recursive: !!args.recursive,
      validOnly: !args["show-all"] && !args["no-valid-only"],
      showAll: !!args["show-all"],
    });
    return;
  }
  if (cmd === "history") {
    const rows = listTraces(parseInt(args.limit || args.n || "50", 10),
      { method: args.method, host: args.host, status: args.status, template: args.template });
    if (!rows.length) return console.log(c("dim", "(empty history — scan first)"));
    for (const e of rows) console.log(`${c("dim", String(e.id).slice(0, 13))} ${String(e.method || "-").padEnd(6)} ${e.status ?? "-"} ${String(e.ms ?? 0).padStart(5)}ms ${(e.url || "").slice(0, 100)} ${c("dim", e.template || "")}`);
    return;
  }
  if (cmd === "show") {
    const e = getTrace(rest[0] || args.id || "");
    if (!e) return console.log("not found. use: netscan history");
    const { _body, ...head } = e;
    console.log(JSON.stringify(head, null, 2));
    console.log(c("dim", "--- body (first 4k) ---"));
    console.log((_body || e.resSnippet || "").slice(0, 4000));
    return;
  }
  if (cmd === "findings") {
    let rows = listFindings(parseInt(args.limit || "100", 10));
    if (!args["show-all"]) rows = rows.filter((f) => !f.candidate);
    if (!rows.length) return console.log(c("dim", "(no valid findings — use --show-all)"));
    for (const f of rows) console.log(`${c("yellow", `[${(f.severity || "info").toUpperCase()}]`)} ${f.template} ${f.url} ${c("dim", String(f.traceId || "").slice(0, 13))}${f.candidate ? c("dim", " [candidate:" + (f.reason || "?") + "]") : ""}`);
    return;
  }
  if (cmd === "report") {
    const all = listFindings(100000);
    const rows = args["show-all"] ? all : all.filter((r) => !r.candidate);
    if (!rows.length) return console.log(c("dim", "(no valid findings — scan first)"));
    const agg = targetScore(rows);
    console.log(c("bold", `Score: ${agg.score}/100 (grade ${agg.grade}) from ${rows.length} findings (${agg.counts.uniqueTemplates} unique)`));
    console.log(`  critical: ${agg.counts.critical}  high: ${agg.counts.high}  medium: ${agg.counts.medium}  low: ${agg.counts.low}`);
    const top = Object.entries(agg.byCat).sort((a, b) => ((b[1].critical * 15 + b[1].high * 7 + b[1].medium * 3 + b[1].low) - (a[1].critical * 15 + a[1].high * 7 + a[1].medium * 3 + a[1].low)));
    for (const [cat, v] of top) console.log(`  ${c("cyan", cat)} C:${v.critical} H:${v.high} M:${v.medium} L:${v.low} I:${v.info || 0} ${c("dim", (v.templates || []).slice(0, 3).join(","))}`);
    const verified = rows.filter((r) => r.verified).length;
    console.log(c("dim", `  verified 2x: ${verified}/${rows.length}`));
    if (!args["show-all"] && all.length > rows.length) console.log(c("dim", `  hidden candidates: ${all.length - rows.length} (use report --show-all)`));
    const sinks = sinkSummary(rows);
    console.log(c("bold", `  Unique vulns (per sink): ${sinks.length}`));
    for (const sk of sinks.slice(0, 30)) {
      const sevC = sk.sev === "critical" || sk.sev === "high" ? "red" : sk.sev === "medium" ? "yellow" : "dim";
      console.log(`  ${c(sevC, `[${String(sk.sev).toUpperCase()}]`)} ${sk.cat} ${sk.path}${sk.param ? " [" + sk.param + "]" : ""} ${c("dim", `x${sk.n} ex:${sk.ex} verified:${sk.verified}/${sk.n}`)}`);
    }
    const ex = {};
    for (const r of rows) {
      if (r.exploit && r.exploit.rating && r.exploit.rating !== "none") {
        const k = `${r.exploit.rating}:${r.exploit.context}`;
        ex[k] = (ex[k] || 0) + 1;
      }
    }
    if (Object.keys(ex).length) {
      console.log(c("bold", "  Exploitability (XSS context):"));
      for (const [k, v] of Object.entries(ex).sort((a, b) => b[1] - a[1])) console.log(`    ${k}: ${v}`);
    }
    const ow = {};
    for (const r of rows) {
      const k = (r.mapping && r.mapping.owasp) || "—";
      ow[k] = (ow[k] || 0) + 1;
    }
    console.log(c("bold", "  OWASP:"));
    for (const [k, v] of Object.entries(ow).sort((a, b) => b[1] - a[1])) console.log(`    ${k}: ${v}`);
    return;
  }
  if (cmd === "clear") { clearAll(); console.log("history+findings wiped"); return; }
  console.log(`unknown: ${cmd}`); help();
}

function splitTags(a) {
  return a.flatMap((s) => String(s).split(",")).map((s) => s.trim().toLowerCase()).filter(Boolean);
}

main().catch((e) => { console.error(c("red", "error: ") + e.message); process.exit(1); });
