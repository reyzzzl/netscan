// TODO: add xpath matcher
// FIXME: size matcher ignores headers

export function evalMatchers({ status, headers, body }, matchers = [], matchAll = false) {
  if (!matchers.length) return false;
  const head = JSON.stringify(headers || {});
  const results = matchers.map((m) => {
    const part = (m.part || "body").toLowerCase();
    const hay = part === "headers" ? head : part === "all" ? body + "\n" + head : body;
    switch ((m.type || "").toLowerCase()) {
      case "word": {
        const words = m.words || m.word || [];
        const arr = Array.isArray(words) ? words : [words];
        const neg = m.negative === true;
        const hayC = m.nocase ? hay.toLowerCase() : hay;
        const hit = arr.some((w) => hayC.includes(m.nocase ? String(w).toLowerCase() : w));
        return neg ? !hit : hit;
      }
      case "regex": {
        const arr = arrOf(m.regex || m.pattern);
        try {
          const flags = m.nocase ? "si" : "s";
          const hit = arr.some((p) => new RegExp(p, flags).test(hay));
          return m.negative === true ? !hit : hit;
        } catch { return false; }
      }
      case "status": {
        const want = arrOf(m.status).map(Number);
        return want.includes(Number(status));
      }
      case "size": {

        const len = (body || "").length;
        if (Array.isArray(m.size)) return len >= m.size[0] && len <= m.size[1];
        if (m.min) return len >= Number(m.min);
        if (m.max) return len <= Number(m.max);
        return false;
      }
      case "time": {
        // Latency judged by engine, never here.
        return false;
      }
      default: return false;
    }
  });
  return matchAll ? results.every(Boolean) : results.some(Boolean);
}

function arrOf(v) { return v === undefined ? [] : Array.isArray(v) ? v.flat() : [v]; }
