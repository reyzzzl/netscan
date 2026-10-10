// TODO: cap trace body size
// FIXME: abort timer leaks on edge
import { logTrace } from "./store.js";
import { shortBody } from "./util.js";


export async function tracedFetch(url, { method = "GET", headers = {}, body = null, template = "", timeoutMs = 15000 } = {}) {
  const t0 = Date.now();
  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), timeoutMs);
  let res, text = "", status = 0, resHeaders = {}, err = null;
  try {
    res = await fetch(url, { method, headers, body, signal: ctrl.signal, redirect: "manual" });
    status = res.status;
    res.headers.forEach((v, k) => (resHeaders[k] = v));
    text = await res.text();
  } catch (e) { err = e.message; }
  finally { clearTimeout(to); }
  const ms = Date.now() - t0;
  const entry = logTrace({
    type: "http", template, method, url,
    reqHeaders: headers, reqBody: (body || "").toString().slice(0, 4000),
    status, resHeaders, resLen: text.length,
    resSnippet: shortBody(text, 500),
    ms, error: err,
    _body: text.slice(0, 20000),
  });
  return { status, headers: resHeaders, body: text, _body: text.slice(0, 20000), ms, error: err, traceId: entry.id };
}
