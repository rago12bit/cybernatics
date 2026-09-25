import { OWASP_2021 } from "./owasp";

// Link builders for data that comes from scanned (untrusted) repositories and scanner output.
// Rule: never put an unvalidated string into an href.

const CVE = /^CVE-\d{4}-\d{4,}$/i;
const CWE = /^CWE-(\d{1,5})$/i;
const OWASP = /^A(0[1-9]|10):2021$/;

export function safeHttpsUrl(raw: string): string | null {
  try {
    const u = new URL(raw);
    return u.protocol === "https:" && !u.username && !u.password ? u.toString() : null;
  } catch {
    return null;
  }
}

export function cweUrl(id: string): string | null {
  const m = CWE.exec(id);
  return m ? `https://cwe.mitre.org/data/definitions/${m[1]}.html` : null;
}

export function cveUrl(id: string): string | null {
  return CVE.test(id) ? `https://nvd.nist.gov/vuln/detail/${id.toUpperCase()}` : null;
}

export function owaspUrl(id: string): string | null {
  return OWASP.test(id) ? `https://top10.owasp.org/${OWASP_2021[id]!.slug}/` : null;
}
