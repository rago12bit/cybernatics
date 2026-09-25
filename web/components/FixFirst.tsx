"use client";

import { useEffect, useState } from "react";
import { locationLabel } from "@/lib/format";
import { defaultQuery } from "@/lib/format";
import type { Finding, FindingsPage, FindingsQuery } from "@/lib/types";
import { RiskSignals, SeverityBadge } from "./Badges";

type Fetcher = (id: string, q: FindingsQuery, limit?: number) => Promise<FindingsPage>;
const TOP = 10;

/** The headline view: the ten findings most worth fixing first, ranked by risk (severity x exploit likelihood). */
export function FixFirst({ scanId, version, fetchFindings, onOpen }: { scanId: string; version: number; fetchFindings: Fetcher; onOpen: (f: Finding, el: HTMLElement) => void }) {
  const [items, setItems] = useState<Finding[] | null>(null);
  useEffect(() => {
    let cancelled = false;
    fetchFindings(scanId, { ...defaultQuery(), sort: "risk" }, TOP).then(
      (p) => { if (!cancelled) setItems(p.items); },
      () => { if (!cancelled) setItems([]); },
    );
    return () => { cancelled = true; };
  }, [scanId, version, fetchFindings]);

  // Older scans (before risk scoring) have no scores: show nothing rather than a meaningless ranking.
  if (!items || items.length === 0 || items.every((f) => f.scoring.risk_score == null)) return null;
  return (
    <section className="fixfirst" aria-labelledby="fix-h">
      <div className="app-head">
        <span className="eyebrow">Fix these first</span>
        <h2 id="fix-h" className="h1">Top {items.length} <span className="muted">by risk</span></h2>
        <p className="small muted">Ranked by severity and how likely each one is to be exploited: CISA&apos;s known-exploited list and EPSS. A heuristic for ordering work, not a guarantee.</p>
      </div>
      <ol className="fixlist">
        {items.map((f, i) => (
          <li key={f.id}>
            <span className="rank" aria-hidden="true">{i + 1}</span>
            <div className="fix-main">
              <button type="button" className="row-title" onClick={(e) => onOpen(f, e.currentTarget)}><span className="clamp">{f.title}</span></button>
              <code className="loc">{locationLabel(f)}</code>
            </div>
            <div className="fix-side">
              <SeverityBadge severity={f.scoring.normalized_severity} />
              <RiskSignals score={f.scoring.risk_score} kev={f.scoring.in_cisa_kev} epss={f.scoring.epss_score} />
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
