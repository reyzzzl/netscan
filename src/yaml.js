// TODO: support folded blocks
// FIXME: deep indent misparses


export function parseSimpleYaml(text) {
  const lines = text.split(/\r?\n/).map((l) => ({ raw: l, indent: (l.match(/^ */) || [""])[0].length, text: l.trim() }))
    .filter((l) => l.text && !l.text.startsWith("#"));
  let i = 0;
  function parseBlock(minIndent) {
    let obj = null;
    while (i < lines.length) {
      const l = lines[i];
      if (l.indent < minIndent) break;
      if (l.indent > minIndent) { i++; continue; }
      if (l.text.startsWith("- ")) {
        if (!Array.isArray(obj)) obj = [];
        const rest = l.text.slice(2).trim();
        if (!rest) { i++; obj.push(parseBlock(minIndent + 2) ?? {}); continue; }
        const kv = splitKV(rest);
        if (kv) {
          i++;
          const child = { [kv[0]]: parseValue(kv[1]) };
          const nested = parseBlock(minIndent + 2);
          if (nested && typeof nested === "object" && !Array.isArray(nested)) Object.assign(child, nested);

          obj.push(child);
        } else { obj.push(parseValue(rest)); i++; }
      } else {
        const kv = splitKV(l.text);
        if (!kv) { i++; continue; }
        if (obj === null) obj = {};
        if (Array.isArray(obj)) break;
        const k = kv[0];
        const v = kv[1].trim();
        if (v === "" || v === "|" || v === ">") {
          i++;
          obj[k] = parseBlock(minIndent + 2) ?? "";
        } else if (v.startsWith("[") && v.endsWith("]")) {
          obj[k] = splitInlineList(v.slice(1, -1)).map((s) => strip(s.trim())).filter((s) => s !== "");
          i++;
        } else {
          const next = lines[i + 1];
          if (next && next.indent > minIndent && !next.text.startsWith("- ") && v === "") {
            i++;
            obj[k] = parseBlock(next.indent) ?? "";
          } else if (next && next.indent > minIndent && next.text.startsWith("- ") && v === "") {
            i++;
            obj[k] = parseBlock(next.indent) ?? [];
          } else { obj[k] = parseValue(v); i++; }
        }
      }
    }
    return obj;
  }
  return parseBlock(0) || {};
}

function splitKV(s) {

  let q = null;
  for (let n = 0; n < s.length; n++) {
    const ch = s[n];
    if (q) {
      if (ch === q && s[n - 1] !== "\\") q = null;
      continue;
    }
    if (ch === '"' || ch === "'") q = ch;
    else if (ch === ":") {
      const after = s[n + 1] || "";
      if (after === "" || after === " " || after === "\t") return [s.slice(0, n).trim(), s.slice(n + 1)];
    }
  }
  return null;
}

function splitInlineList(s) {
  const out = [];
  let cur = "", q = null;
  for (let n = 0; n < s.length; n++) {
    const ch = s[n];
    if (q) {
      cur += ch;
      if (ch === q && s[n - 1] !== "\\") q = null;
      continue;
    }
    if (ch === '"' || ch === "'") { q = ch; cur += ch; }
    else if (ch === ",") { out.push(cur); cur = ""; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

function parseValue(v) {
  const t = v.trim();
  if (t === "true") return true;
  if (t === "false") return false;
  if (t === "null" || t === "~") return null;
  if (/^-?\d+$/.test(t)) return parseInt(t, 10);
  if (/^-?\d+\.\d+$/.test(t)) return parseFloat(t);
  return strip(t);
}

function strip(s) {
  if (s.length >= 2 && s.startsWith("'") && s.endsWith("'")) {
    return s.slice(1, -1).replace(/''/g, "'");
  }
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
    return s.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\").replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "\t");
  }
  return s;
}
