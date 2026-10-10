// TODO: cover nested attr contexts
// FIXME: null gap skips breakout check
import { evalMatchers } from "./match.js";
import { rateXss } from "./context.js";


export const BASELINE_TOKEN = "nscanbase9";

export function isStatusOnly(matchers = []) {
  if (!matchers.length) return false;
  return matchers.every((m) => ["status", "size", "time"].includes(String(m.type || "").toLowerCase()));
}

export function effectiveMatchers(req, t) {
  if (req && Array.isArray(req.matchers) && req.matchers.length) return req.matchers;
  return (t && t.matchers) || [];
}


export function baselineUrl(jobUrl, param) {
  if (!param) return null;
  try {
    const u = new URL(jobUrl);
    if (!u.searchParams.has(param)) return null;
    u.searchParams.set(param, BASELINE_TOKEN);
    return u.toString();
  } catch { return null; }
}

export function xssCanary(body, matchers = []) {
  const html = String(body || "");
  for (const m of matchers) {
    if (String(m.type || "").toLowerCase() !== "word") continue;
    const arr = Array.isArray(m.words) ? m.words : (m.words === undefined ? [] : [m.words]);
    const arr2 = m.word !== undefined ? [...arr, ...(Array.isArray(m.word) ? m.word : [m.word])] : arr;
    for (const w of arr2) {
      if (w && html.includes(String(w))) return String(w);
    }
  }
  return null;
}

export function judgeXss(body, matchers = [], gap = null) {
  const canary = xssCanary(body, matchers);
  if (!canary) return { ok: false, rating: "none", context: "not-found", snippet: "", reason: "canary-not-reflected" };
  const v = rateXss(body, canary);
  if (v.rating !== "high" && v.rating !== "medium") {
    const why = v.context === "encoded" ? "encoded (&lt;/&gt;), not executable"
      : v.context === "html-comment" ? "inside HTML comment, not executable"
      : v.context.endsWith("-body") ? `inside <${v.context.replace("-body", "")}>, not executable`
      : `context ${v.context}, not executable`;
    return { ok: false, ...v, reason: `xss-${v.context}: ${why}` };
  }
  if (gap === null || gap === undefined) return { ok: true, ...v };
  if (xssNeed(v.context).test(String(gap))) return { ok: true, ...v };
  return { ok: false, ...v, reason: `xss-${v.context}-no-breakout: raw payload lacks breakout chars here` };
}

function xssNeed(context) {
  if (context.startsWith("attr-double")) return /["]|javascript:|data:text\/html/i;
  if (context.startsWith("attr-single")) return /['"]|javascript:|data:text\/html/i;
  if (context.startsWith("attr-unquoted")) return /[\s>"']/;
  if (context.startsWith("js-")) return /['"`]/;
  if (context.startsWith("tag-")) return /[>"']/;
  return /</;
}

export function reflectionGap(injected, baseline, cap = 5000) {
  const a = String(injected || ""), b = String(baseline || "");
  if (!a || !b) return null;
  let pre = 0;
  const maxPre = Math.min(a.length, b.length);
  while (pre < maxPre && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < Math.min(a.length - pre, b.length - pre) && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  const gap = a.slice(pre, a.length - suf);
  if (!gap || gap.length > cap) return null;
  return gap;
}

function payloadVariants(payload) {
  const out = [String(payload)];
  try {
    const dec = decodeURIComponent(String(payload).replace(/\+/g, " "));
    if (dec && dec !== out[0]) out.push(dec);
  } catch {}
  return out.filter(Boolean);
}

export function stripEcho(body, payload) {
  let s = String(body || "");
  for (const v of payloadVariants(payload)) {
    if (v.length < 2) continue;
    s = s.split(v).join("");
  }
  return s;
}

export function echoFreeHit(res, matchers = [], matchAll = false, payload = "") {
  const nonTime = matchers.filter((m) => String(m.type || "").toLowerCase() !== "time");
  if (!nonTime.length || !payload) return true;
  const bodyM = nonTime.filter((m) => (m.part || "body").toLowerCase() !== "headers");
  if (!bodyM.length) return true;
  const stripped = stripEcho(res.body, payload);
  if (stripped === res.body) return true;
  const rest = { ...res, body: stripped };
  const results = nonTime.map((m) => evalMatchers(rest, [m], false));
  return matchAll ? results.every(Boolean) : results.some(Boolean);
}
