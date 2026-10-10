// TODO: map nosql tag
// FIXME: misc tag hides gaps

const MAP = {
  "xss": { owasp: "A03:2021 – Injection", cwe: ["CWE-79"] },
  "sqli": { owasp: "A03:2021 – Injection", cwe: ["CWE-89"] },
  "ssti": { owasp: "A03:2021 – Injection", cwe: ["CWE-94"] },
  "cmdi": { owasp: "A03:2021 – Injection", cwe: ["CWE-78"] },
  "nosql": { owasp: "A03:2021 – Injection", cwe: ["CWE-943"] },
  "crlf": { owasp: "A03:2021 – Injection", cwe: ["CWE-113"] },
  "lfi": { owasp: "A01:2021 – Broken Access Control", cwe: ["CWE-22"] },
  "bypass": { owasp: "A01:2021 – Broken Access Control", cwe: ["CWE-284"] },
  "mass-assignment": { owasp: "A01:2021 – Broken Access Control", cwe: ["CWE-915"] },
  "redirect": { owasp: "A01:2021 – Broken Access Control", cwe: ["CWE-601"] },
  "cors": { owasp: "A01:2021 – Broken Access Control", cwe: ["CWE-942"] },
  "graphql": { owasp: "A01:2021 – Broken Access Control", cwe: ["CWE-200"] },
  "secret": { owasp: "A04:2021 – Insecure Design", cwe: ["CWE-200"] },
  "ssrf": { owasp: "A10:2021 – SSRF", cwe: ["CWE-918"] },
  "xxe": { owasp: "A05:2021 – Misconfiguration", cwe: ["CWE-611"] },
  "headers": { owasp: "A05:2021 – Misconfiguration", cwe: ["CWE-693"] },
  "backup": { owasp: "A05:2021 – Misconfiguration", cwe: ["CWE-538"] },
  "exposure": { owasp: "A05:2021 – Misconfiguration", cwe: ["CWE-538"] },
  "error": { owasp: "A05:2021 – Misconfiguration", cwe: ["CWE-209"] },
  "fingerprint": { owasp: "A05:2021 – Misconfiguration", cwe: ["CWE-200"] },
  "info": { owasp: "A05:2021 – Misconfiguration", cwe: ["CWE-200"] },
  "auth": { owasp: "A07:2021 – Auth Failures", cwe: ["CWE-287"] },
  "jwt": { owasp: "A07:2021 – Auth Failures", cwe: ["CWE-287"] },
  "cve": { owasp: "A06:2021 – Vulnerable Components", cwe: ["CWE-1104"] },
};

export function mappingFor(tags = []) {
  for (const t of tags || []) {
    const m = MAP[String(t).toLowerCase()];
    if (m) return { tag: String(t).toLowerCase(), ...m };
  }
  return { tag: "misc", owasp: "—", cwe: [] };
}
