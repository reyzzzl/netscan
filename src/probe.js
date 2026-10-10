import { evalMatchers } from "./match.js";

// TODO: rotate probe canary
// FIXME: 49 collides with real data
// Cheap layer-0 probes. One request per (page, param) opens the gate.

export const PROBES = {
  xss: {
    payload: () => "NXGPX<svg/onload=NXGPX>",
    matchers: [{ type: "word", part: "body", words: ["NXGPX"] }],
    fallback: ["q"],
    patt: "PATT XSS space-bypass <svg/onload>",
    patt_source:
      "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/README.md",
  },
  sqli: {
    payload: () => "'NXGPQ",
    matchers: [{ type: "regex", part: "body", regex: ["SQL syntax", "mysql", "ORA-", "PostgreSQL", "SQLite", "ODBC", "JDBC", "DB2", "Sybase", "Informix", "JET", "Firebird", "HSQLDB", "MaxDB", "CockroachDB"] }],
    fallback: ["id"],
    patt: "PATT MySQL boolean quote-trigger",
    patt_source:
      "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/MySQL%20Injection.md",
  },
  ssti: {
    payload: () => "{{7*7}}NXGPS",
    matchers: [{ type: "word", part: "body", words: ["49"] }],
    fallback: ["template"],
    patt: "PATT SSTI universal detection {{7*7}}",
    patt_source:
      "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/README.md",
  },
  cmdi: {
    payload: () => ";echo NXGPC",
    matchers: [{ type: "word", part: "body", words: ["uid=", "NXGPC"] }],
    fallback: ["cmd"],
    patt: "PATT Command Injection chaining semicolon",
    patt_source:
      "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/README.md",
  },
  lfi: {
    payloads: () => ["../../../../etc/passwd", "..%252f..%252f..%252fetc%252fpasswd"],
    matchers: [{ type: "word", part: "body", words: ["root:x"] }],
    fallback: ["file"],
    patt: "PATT Directory Traversal baseline + double-encode",
    patt_source:
      "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/README.md",
  },
};

export function probeFor(family, param) {
  const def = PROBES[family];
  if (!def) return null;
  const pays = def.payloads ? def.payloads() : [def.payload()];
  return { pays, matchers: def.matchers, fallback: def.fallback };
}

export function detectProbe(res, matchers) {
  return evalMatchers(res, matchers, false);
}
