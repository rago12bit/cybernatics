// Numbers from benchmarks/results/dedup-2026-09-25-v2-aligned-scope.json (measured 2026-09-25).
// They are copied here, not invented: update this file when the benchmark is re-run.
export const BENCHMARK = {
  measuredOn: "2026-09-25",
  source: "benchmarks/results/dedup-2026-09-25-v2-aligned-scope.json",
  raw: 2552,
  unique: 1824,
  dedupRate: 0.2853,
  repos: [
    { name: "VAmPI", full: "VAmPI", raw: 23, unique: 21, dedup: 0.087, merged: 2 },
    { name: "NodeGoat", full: "NodeGoat", raw: 771, unique: 463, dedup: 0.3995, merged: 291 },
    { name: "goof", full: "nodejs-goof", raw: 601, unique: 305, dedup: 0.4925, merged: 284 },
    { name: "Flask-App", full: "Vulnerable-Flask-App", raw: 212, unique: 155, dedup: 0.2689, merged: 48 },
    { name: "terragoat", full: "terragoat", raw: 945, unique: 880, dedup: 0.0688, merged: 65 },
  ],
  rawPerScanner: [
    { tool: "trivy", raw: 1505 },
    { tool: "osv-scanner", raw: 793 },
    { tool: "semgrep", raw: 222 },
    { tool: "bandit", raw: 23 },
    { tool: "gitleaks", raw: 9 },
  ],
};
