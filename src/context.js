// TODO: handle svg context
// FIXME: only first canary rated


export function rateXss(body, canary) {
  const html = String(body || "");
  const idx = html.indexOf(canary);
  if (idx === -1) return { context: "not-found", rating: "none", snippet: "" };
  const before = html.slice(Math.max(0, idx - 300), idx);
  const after = html.slice(idx, idx + 60);
  const snippet = (before.slice(-80) + "[[CANARY]]" + after.slice(canary.length, canary.length + 40)).replace(/\n/g, " ");


  const around = html.slice(Math.max(0, idx - 12), idx + canary.length + 12);
  if (/&(lt|gt|quot|#x?[0-9a-f]+);/i.test(around)) return { context: "encoded", rating: "low", snippet };


  const openC = before.lastIndexOf("<!--");
  const closeC = before.lastIndexOf("-->");
  if (openC > closeC) return { context: "html-comment", rating: "low", snippet };


  const openS = before.toLowerCase().lastIndexOf("<script");
  const closeS = before.toLowerCase().lastIndexOf("</script>");
  if (openS > closeS) {

    const seg = before.slice(openS);
    const sq = (seg.match(/'/g) || []).length;
    const dq = (seg.match(/"/g) || []).length;
    if (sq % 2 === 1 || dq % 2 === 1) return { context: "js-string", rating: "high", snippet };
    return { context: "js-body", rating: "high", snippet };
  }


  const tagM = before.match(/<(textarea|title|style|noscript)[^<>]*$/i);
  if (tagM) return { context: `${tagM[1].toLowerCase()}-body`, rating: "low", snippet };


  const tagOpen = before.lastIndexOf("<");
  const tagClose = before.lastIndexOf(">");
  if (tagOpen > tagClose) {
    const inside = before.slice(tagOpen);
    const dq = (inside.match(/"/g) || []).length;
    const sq = (inside.match(/'/g) || []).length;
    if (/=\s*[^"'=\s<>`]*$/.test(inside) && dq % 2 === 0 && sq % 2 === 0) {
      return { context: "attr-unquoted", rating: "high", snippet };
    }
    if (dq % 2 === 1) return { context: "attr-double", rating: "medium", snippet };
    if (sq % 2 === 1) return { context: "attr-single", rating: "medium", snippet };
    return { context: "tag-text", rating: "medium", snippet };
  }


  if (/[<>]/.test(around)) return { context: "html-body-raw", rating: "high", snippet };
  return { context: "html-body-text", rating: "medium", snippet };
}
