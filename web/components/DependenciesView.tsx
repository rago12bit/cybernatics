"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { ApiError, getDependencies } from "@/lib/api";
import type { DependenciesView as DependenciesData, DependencyPackage, DependencyRelation } from "@/lib/types";
import "./dependencies-view.css";

const RELATION_LABEL: Record<DependencyRelation, string> = {
  direct: "Direct",
  transitive: "Transitive",
  root: "Root",
  unknown: "Unknown",
};

/** The shortest root-to-`targetPurl` path over the SBOM's own dependency graph, root first -- the
 * same algorithm `core.supplychain.dependency_view.path_to` runs server-side, run here client-side
 * since the whole graph (every package's own `depends_on`) is already in the one API response.
 * `null` when there is no route: no relationship data for this manifest (a bare, unlocked
 * manifest), or `targetPurl` isn't in this SBOM at all. */
function pathTo(packages: DependencyPackage[], targetPurl: string): string[] | null {
  const byPurl = new Map(packages.map((p) => [p.purl, p]));
  const roots = packages.filter((p) => p.relation === "root").map((p) => p.purl);
  if (roots.includes(targetPurl)) return [targetPurl];
  const visited = new Set(roots);
  const queue: Array<{ purl: string; path: string[] }> = roots.map((purl) => ({ purl, path: [purl] }));
  while (queue.length > 0) {
    const { purl, path } = queue.shift() as { purl: string; path: string[] };
    for (const child of byPurl.get(purl)?.depends_on ?? []) {
      if (child === targetPurl) return [...path, child];
      if (!visited.has(child)) {
        visited.add(child);
        queue.push({ purl: child, path: [...path, child] });
      }
    }
  }
  return null;
}

function ScorecardBadge({ score }: { score: number }) {
  const level = score >= 7 ? "good" : score >= 4 ? "fair" : "poor";
  return (
    <span className={`ds-deps-scorecard ds-deps-scorecard-${level}`} title={`OpenSSF Scorecard: ${score.toFixed(1)} / 10`}>
      {score.toFixed(1)}
    </span>
  );
}

function PackageRow({
  pkg,
  packages,
  expanded,
  onToggle,
}: {
  pkg: DependencyPackage;
  packages: DependencyPackage[];
  expanded: boolean;
  onToggle: () => void;
}) {
  const path = expanded ? pathTo(packages, pkg.purl) : null;
  return (
    <>
      <tr className="ds-deps-row" onClick={onToggle} aria-expanded={expanded}>
        <td>
          <span className="ds-deps-name">{pkg.name}</span>
          <span className="ds-deps-version">{pkg.version}</span>
        </td>
        <td>{pkg.ecosystem}</td>
        <td>
          <span className={`ds-deps-relation ds-deps-relation-${pkg.relation}`}>{RELATION_LABEL[pkg.relation]}</span>
        </td>
        <td>{pkg.license || <span className="muted">unknown</span>}</td>
        <td>{pkg.scorecard ? <ScorecardBadge score={pkg.scorecard.score} /> : <span className="muted">—</span>}</td>
      </tr>
      {expanded && (
        <tr className="ds-deps-detail-row">
          <td colSpan={5}>
            <div className="ds-deps-detail">
              <div>
                <span className="ds-deps-detail-label">Path from root</span>
                {path ? (
                  <ol className="ds-deps-path">
                    {path.map((purl) => (
                      <li key={purl}>{packages.find((p) => p.purl === purl)?.name ?? purl}</li>
                    ))}
                  </ol>
                ) : (
                  <p className="muted small">
                    No dependency-graph data for this package (a bare, unlocked manifest has no resolved tree to report).
                  </p>
                )}
              </div>
              {pkg.depends_on.length > 0 && (
                <div>
                  <span className="ds-deps-detail-label">Depends on</span>
                  <ul className="ds-deps-children">
                    {pkg.depends_on.map((purl) => (
                      <li key={purl}>{packages.find((p) => p.purl === purl)?.name ?? purl}</li>
                    ))}
                  </ul>
                </div>
              )}
              {pkg.scorecard && (
                <div>
                  <span className="ds-deps-detail-label">OpenSSF Scorecard checks</span>
                  <ul className="ds-deps-checks">
                    {Object.entries(pkg.scorecard.checks).map(([check, score]) => (
                      <li key={check}>
                        {check} <span className="muted">{score}/10</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * Plan §20.5's Dependencies screen: the asset's latest SBOM -- every package, direct versus
 * transitive, each one's own path from the project root, license, and (for direct dependencies)
 * OpenSSF Scorecard. Built entirely from `GET /assets/{id}/dependencies` (api/schemas.py's
 * DependenciesView, itself `Scan.sbom_summary`, populated by `core/pipeline.py::_process_sbom`
 * when a scan opts "syft" into its tools) -- nothing here is fabricated.
 */
export function DependenciesView({ assetId }: { assetId: string }) {
  const [data, setData] = useState<DependenciesData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [relation, setRelation] = useState<DependencyRelation | "">("");
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setData(null);
    setError(null);
    getDependencies(assetId).then(
      (d) => { if (!cancelled) setData(d); },
      (e) => { if (!cancelled) setError(e instanceof ApiError ? e.message : "Failed to load dependencies"); },
    );
    return () => { cancelled = true; };
  }, [assetId]);

  const filtered = useMemo(() => {
    if (!data) return [];
    const q = search.trim().toLowerCase();
    return data.packages
      .filter((p) => !relation || p.relation === relation)
      .filter((p) => !q || p.name.toLowerCase().includes(q) || p.ecosystem.toLowerCase().includes(q))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [data, search, relation]);

  if (error) return <div className="ds-deps-empty" role="alert">{error}</div>;
  if (!data) {
    return (
      <div className="ds-deps" role="status" aria-busy="true">
        <span className="sr-only">Loading dependencies…</span>
        <div className="ds-deps-summary"><span className="sk sk-l" style={{ height: "2rem" }} /></div>
      </div>
    );
  }

  if (data.components === 0) {
    return (
      <div className="ds-deps-empty">
        <p>No SBOM for this project yet.</p>
        <p className="muted small">
          Start a new scan with <code>syft</code> selected under &quot;Supply-chain risk&quot; to populate this screen.
        </p>
      </div>
    );
  }

  const direct = data.packages.filter((p) => p.relation === "direct").length;
  const transitive = data.packages.filter((p) => p.relation === "transitive").length;

  return (
    <div className="ds-deps">
      <div className="ds-deps-crumbline">
        <Link href={`/app/projects/${assetId}`}>overview</Link> <span aria-hidden="true">·</span>{" "}
        <Link href={`/app/projects/${assetId}/issues`}>all issues</Link>
        {data.scan_id && (
          <>
            {" "}
            <span aria-hidden="true">·</span> <Link href={`/scans/${data.scan_id}`}>full scan report</Link>
          </>
        )}
      </div>

      <div className="ds-deps-summary">
        <div>
          <span className="ds-deps-summary-num">{data.components}</span>
          <span className="ds-deps-summary-label">components</span>
        </div>
        <div>
          <span className="ds-deps-summary-num">{direct}</span>
          <span className="ds-deps-summary-label">direct</span>
        </div>
        <div>
          <span className="ds-deps-summary-num">{transitive}</span>
          <span className="ds-deps-summary-label">transitive</span>
        </div>
        <div className="ds-deps-ecosystems">
          {Object.entries(data.ecosystems).map(([eco, count]) => (
            <span key={eco} className="ds-deps-chip">
              {eco} <span className="muted">{count}</span>
            </span>
          ))}
        </div>
      </div>

      <div className="ds-deps-toolbar">
        <input
          type="search"
          placeholder="Filter by name or ecosystem…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Filter dependencies"
        />
        <select value={relation} onChange={(e) => setRelation(e.target.value as DependencyRelation | "")} aria-label="Filter by relation">
          <option value="">All relations</option>
          <option value="direct">Direct</option>
          <option value="transitive">Transitive</option>
          <option value="root">Root</option>
          <option value="unknown">Unknown</option>
        </select>
      </div>

      <table className="ds-deps-table">
        <thead>
          <tr>
            <th>Package</th>
            <th>Ecosystem</th>
            <th>Relation</th>
            <th>License</th>
            <th>Scorecard</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((p) => (
            <PackageRow
              key={p.purl}
              pkg={p}
              packages={data.packages}
              expanded={expanded === p.purl}
              onToggle={() => setExpanded((cur) => (cur === p.purl ? null : p.purl))}
            />
          ))}
        </tbody>
      </table>
      {filtered.length === 0 && <p className="muted small">No dependencies match this filter.</p>}
    </div>
  );
}
