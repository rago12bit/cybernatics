// OWASP Top 10:2021 categories. Keep in sync with core/taxonomy/owasp_top10_2021.json (the Python
// side owns the CWE mapping; the UI only needs names and links). Tested in tests/lib.test.ts.
export const OWASP_2021: Record<string, { name: string; slug: string }> = {
  "A01:2021": { name: "Broken Access Control", slug: "A01_2021-Broken_Access_Control" },
  "A02:2021": { name: "Cryptographic Failures", slug: "A02_2021-Cryptographic_Failures" },
  "A03:2021": { name: "Injection", slug: "A03_2021-Injection" },
  "A04:2021": { name: "Insecure Design", slug: "A04_2021-Insecure_Design" },
  "A05:2021": { name: "Security Misconfiguration", slug: "A05_2021-Security_Misconfiguration" },
  "A06:2021": { name: "Vulnerable and Outdated Components", slug: "A06_2021-Vulnerable_and_Outdated_Components" },
  "A07:2021": { name: "Identification and Authentication Failures", slug: "A07_2021-Identification_and_Authentication_Failures" },
  "A08:2021": { name: "Software and Data Integrity Failures", slug: "A08_2021-Software_and_Data_Integrity_Failures" },
  "A09:2021": { name: "Security Logging and Monitoring Failures", slug: "A09_2021-Security_Logging_and_Monitoring_Failures" },
  "A10:2021": { name: "Server-Side Request Forgery (SSRF)", slug: "A10_2021-Server-Side_Request_Forgery_%28SSRF%29" },
};

export function owaspLabel(id: string): string {
  const e = Object.prototype.hasOwnProperty.call(OWASP_2021, id) ? OWASP_2021[id] : undefined;
  return e ? `OWASP ${id.slice(0, 3)} ${e.name}` : `OWASP ${id}`;
}
