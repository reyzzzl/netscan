// TODO: add NO_COLOR support
// FIXME: shortBody splits surrogates
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const C = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m",
  blue: "\x1b[34m", magenta: "\x1b[35m", cyan: "\x1b[36m",
};
export const c = (color, s) =>
  process.stdout.isTTY ? `${C[color]}${s}${C.reset}` : `${s}`;

export function dataDir() {
  const d = process.env.NETSCAN_DIR || path.join(os.homedir(), ".netscan");
  fs.mkdirSync(d, { recursive: true });
  return d;
}

export function parseArgs(argv) {
  const args = { _: [] };
  let key = null;
  for (let i = 2; i < argv.length; i++) {
    const t = argv[i];
    if (t === "--") { args._.push(...argv.slice(i + 1)); break; }
    else if (t.startsWith("--")) {
      const eq = t.indexOf("=");
      if (eq > -1) { args[t.slice(2, eq)] = t.slice(eq + 1); key = null; }
      else { key = t.slice(2); args[key] = true; }
    } else if (t.startsWith("-") && t.length === 2) {
      key = t.slice(1); args[key] = true;
    } else if (key) {
      if (args[key] === true) args[key] = t;
      else if (Array.isArray(args[key])) args[key].push(t);
      else args[key] = [args[key], t].flat();
      key = null;
    } else args._.push(t);
  }
  return args;
}

export const arr = (v) => v === undefined ? [] : Array.isArray(v) ? v.flat() : [v];
export const now = () => new Date().toISOString();
export const shortBody = (buf, n = 500) => String(buf ?? "").slice(0, n).replace(/\n/g, "\\n");
