// TODO: rotate history file
// FIXME: append races under threads
import fs from "node:fs";
import path from "node:path";
import { dataDir, now } from "./util.js";

function histFile() { return path.join(dataDir(), "history.jsonl"); }
function findingsFile() { return path.join(dataDir(), "findings.jsonl"); }

export function logTrace(e) {
  const line = JSON.stringify({ id: `${Date.now()}-${Math.floor(Math.random() * 1e6)}`, time: now(), ...e });
  fs.appendFileSync(histFile(), line + "\n");
  return JSON.parse(line);
}

export function logFinding(f) {
  const line = JSON.stringify({ time: now(), ...f });
  fs.appendFileSync(findingsFile(), line + "\n");
  return JSON.parse(line);
}

export function listTraces(limit = 50, filter = {}) {
  let lines = [];
  try { lines = fs.readFileSync(histFile(), "utf8").trim().split("\n").filter(Boolean); }
  catch { return []; }
  let out = lines.map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  if (filter.method) out = out.filter((e) => (e.method || "").toUpperCase() === String(filter.method).toUpperCase());
  if (filter.host) out = out.filter((e) => (e.url || "").includes(filter.host));
  if (filter.status) out = out.filter((e) => String(e.status) === String(filter.status));
  if (filter.template) out = out.filter((e) => (e.template || "").includes(filter.template));
  return out.slice(-limit);
}

export function getTrace(id) {
  return listTraces(100000).find((e) => e.id === id || e.id.startsWith(id));
}

export function listFindings(limit = 100) {
  try {
    return fs.readFileSync(findingsFile(), "utf8").trim().split("\n").filter(Boolean)
      .map((l) => JSON.parse(l)).slice(-limit);
  } catch { return []; }
}

export function clearAll() {
  try { fs.unlinkSync(histFile()); } catch {}
  try { fs.unlinkSync(findingsFile()); } catch {}
}
