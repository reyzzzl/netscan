// TODO: respect robots meta
// FIXME: srcset links missed

export function extractUrls(html, base) {
  const out = new Set();
  const push = (u) => {
    try {
      const abs = new URL(u, base).toString();
      const b = new URL(base);
      if (new URL(abs).host === b.host && abs.startsWith("http")) out.add(abs.split("#")[0]);
    } catch {}
  };
  for (const m of html.matchAll(/href\s*=\s*["']([^"'#]+)["']/gi)) push(m[1]);
  for (const m of html.matchAll(/action\s*=\s*["']([^"'#]+)["']/gi)) push(m[1]);
  for (const m of html.matchAll(/src\s*=\s*["']([^"'#]+)["']/gi)) push(m[1]);
  for (const m of html.matchAll(/fetch\s*\(\s*["']([^"']+)["']/g)) push(m[1]);
  for (const m of html.matchAll(/["'](\/(api|v\d+)[^"']*)["']/g)) push(m[1]);
  return [...out].slice(0, 50);
}

export function sameHost(a, b) {
  try { return new URL(a).host === new URL(b).host; } catch { return false; }
}

export function normUrl(u) {
  try {
    const x = new URL(u);
    x.hash = "";
    return x.toString();
  } catch { return String(u).split("#")[0]; }
}


export async function crawlRecursive(startUrl, { depth = 1, limit = 20, fetchFn } = {}) {
  const seen = new Set([normUrl(startUrl)]);
  const order = [startUrl];
  let frontier = [startUrl];
  let d = 0;
  while (frontier.length && d < depth && order.length < limit) {
    const next = [];
    for (const url of frontier) {
      if (order.length >= limit) break;
      let body = "";
      try {
        const r = await fetchFn(url);
        body = (r && (r._body || r.body)) || "";
      } catch { continue; }
      for (const u of extractUrls(body, url)) {
        if (order.length + next.length >= limit) break;
        if (!sameHost(u, startUrl)) continue;
        const k = normUrl(u);
        if (seen.has(k)) continue;
        seen.add(k);
        next.push(u);
      }
    }
    for (const u of next) order.push(u);
    frontier = next;
    d++;
  }
  return order.slice(0, limit);
}
