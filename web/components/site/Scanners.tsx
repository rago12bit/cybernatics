"use client";

import { useState } from "react";

const SCANNERS = [
  { name: "Semgrep CE", kind: "SAST", license: "LGPL-2.1 engine", text: "Pattern-based static analysis for Python, JavaScript, Go and Java. Rules are loaded per detected language, and run fully offline.", tags: ["code", "offline rules"] },
  { name: "Bandit", kind: "SAST · Python", license: "Apache-2.0", text: "The Python security linter. Its findings are the pathfinder for the adapter interface, and the counterpoint Semgrep is merged against.", tags: ["python", "CWE-mapped"] },
  { name: "Gitleaks", kind: "Secrets", license: "MIT", text: "Finds committed credentials. Output is redacted at the source, and no other scanner's finding may echo the secret either.", tags: ["redacted", "fast"] },
  { name: "Trivy", kind: "SCA · IaC · Dockerfile", license: "Apache-2.0", text: "Dependency vulnerabilities, Terraform and Dockerfile misconfiguration in one integration, on a baked-in vulnerability database.", tags: ["deps + dev deps", "iac", "docker"] },
  { name: "OSV-Scanner", kind: "SCA", license: "Apache-2.0", text: "Google's OSV database over your lockfiles, matched offline. Two independent dependency scanners are what make agreement meaningful.", tags: ["lockfiles", "offline"] },
];

export function Scanners() {
  const [open, setOpen] = useState(0);
  return (
    <div className="ing-list">
      <div className="panel-head green"><span className="eyebrow plain">Scanners</span><span className="label dimmed">{SCANNERS.length} run by default</span></div>
      {SCANNERS.map((s, i) => (
        <div key={s.name} className="ing-item" data-open={open === i}>
          <button type="button" aria-expanded={open === i} onClick={() => setOpen(i)}>
            <span className="ic" aria-hidden="true" />
            <span>{s.name}</span>
            <span className="spacer" />
            <span className="label dimmed">{s.kind}</span>
          </button>
          <div className="detail">
            {s.text}
            <div className="meta">
              <span className="chip">{s.license}</span>
              {s.tags.map((t) => <span key={t} className="chip">{t}</span>)}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
