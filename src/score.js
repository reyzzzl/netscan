// TODO: weight stored higher
// FIXME: secrets skew passive grade


export const SEV_W = { critical: 10, high: 5, medium: 2, low: 0.5, info: 0 };

export function findingScore({ severity = "info", tags = [], type = "active" } = {}) {
  const w = SEV_W[String(severity).toLowerCase()] ?? 0;
  const tl = (tags || []).map((s) => String(s).toLowerCase());
  const conf = tl.includes("secret") ? 1 : type === "passive" ? 0.5 : 1;
  return Math.round(w * conf * 10) / 10;
}


export function targetScore(findings = []) {
  const best = new Map();
  for (const f of findings) {
    if (f.candidate) continue;
    const cur = best.get(f.template);
    const s = findingScore({ severity: f.severity, tags: f.tags, type: f.type });
    if (!cur || s > cur.score) best.set(f.template, { severity: String(f.severity || "info").toLowerCase(), score: s, tags: f.tags || [] });
  }
  let C = 0, H = 0, M = 0, L = 0;
  const byCat = {};
  for (const [tpl, v] of best) {
    if (v.severity === "critical") C++;
    else if (v.severity === "high") H++;
    else if (v.severity === "medium") M++;
    else if (v.severity === "low") L++;
    const cat = (v.tags[0] || "misc").toLowerCase();
    byCat[cat] = byCat[cat] || { critical: 0, high: 0, medium: 0, low: 0, info: 0, templates: [] };
    byCat[cat][v.severity] = (byCat[cat][v.severity] || 0) + 1;
    if (byCat[cat].templates.length < 5) byCat[cat].templates.push(tpl);
  }
  const points = 15 * C + 7 * H + 3 * M + 1 * L;
  const score = Math.min(100, points);
  return { score, grade: gradeFor(score), counts: { critical: C, high: H, medium: M, low: L, uniqueTemplates: best.size }, byCat };
}

export function gradeFor(score) {
  if (score <= 0) return "A";
  if (score <= 9) return "B";
  if (score <= 24) return "C";
  if (score <= 49) return "D";
  if (score <= 79) return "E";
  return "F";
}
