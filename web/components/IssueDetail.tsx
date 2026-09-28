"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, getIssue, getIssueHistory, liveGuidance, triageIssue } from "@/lib/api";
import type { Finding, IssueHistoryEvent } from "@/lib/types";
import { SeverityBadge } from "@/design-system/severity";
import { WhyRankedPanel } from "@/design-system/why-ranked";
import { TaintStepper, type TaintStep } from "@/design-system/taint-stepper";
import { CodeView } from "@/design-system/code-view";
import { Button } from "@/design-system/primitives/Button";
import { Dialog } from "@/design-system/primitives/Dialog";
import { useMode } from "@/design-system/mode";
import "./issue-detail.css";

export function IssueDetail({ assetId, issueId }: { assetId: string; issueId: string }) {
  const { mode, setMode } = useMode();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [history, setHistory] = useState<IssueHistoryEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeStep, setActiveStep] = useState(0);
  const [explanationOpen, setExplanationOpen] = useState(mode === "novice");
  const [aiExplanation, setAiExplanation] = useState<string | null>(null);
  const [triageOpen, setTriageOpen] = useState<"not_a_risk" | "accepted" | null>(null);
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => setExplanationOpen(mode === "novice"), [mode]);

  function reload() {
    getIssue(assetId, issueId).then(setFinding, (e) => setError(e instanceof ApiError ? e.message : "Failed to load this issue"));
    getIssueHistory(assetId, issueId).then(setHistory, () => setHistory([]));
  }
  useEffect(reload, [assetId, issueId]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!finding?.scan_id) return;
    let cancelled = false;
    liveGuidance.get(finding.scan_id, finding.id).then(
      (g) => { if (!cancelled) setAiExplanation(g.ai?.explanation ?? g.static.explanation); },
      () => { /* no guidance available: the panel just shows the finding's own description */ },
    );
    return () => { cancelled = true; };
  }, [finding?.scan_id, finding?.id]);

  async function runTriage(action: "not_a_risk" | "accepted" | "reopen") {
    setBusy(true);
    try {
      const body = action === "not_a_risk" ? { action, reason } : action === "accepted" ? { action, reason, expires_at: expiresAt } : { action };
      await triageIssue(assetId, issueId, body);
      setTriageOpen(null);
      setReason("");
      setExpiresAt("");
      reload();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Triage failed");
    } finally {
      setBusy(false);
    }
  }

  if (error) return <div className="ds-issue-empty" role="alert">{error}</div>;
  if (!finding) return <div className="ds-issue-empty" role="status" aria-live="polite">Loading…</div>;

  // The taint-path stepper (plan §20.3, §28.3): "static until Phase 9 supplies real taint paths."
  // The one real step available today is the finding's own location -- the sink -- never invented
  // intermediate hops.
  const steps: TaintStep[] = [{ path: finding.location.path, line: finding.location.start_line, label: "Where this happens" }];
  const triageStatus = finding.issue?.triage_status ?? "open";

  return (
    <div className="ds-issue">
      <div className="ds-issue-topline">
        <Link href={`/app/projects/${assetId}/issues`}>← Issues</Link>
        <code>{finding.id}</code>
        <span className="ds-issue-topline-title">{finding.title}</span>
        <div className="ds-issue-topline-spacer" />
        <label className="ds-mode-toggle">
          <input type="checkbox" checked={mode === "expert"} onChange={(e) => setMode(e.target.checked ? "expert" : "novice")} />
          Expert mode
        </label>
      </div>

      {triageStatus !== "open" && (
        <div className="ds-issue-triage-banner">
          {triageStatus === "not_a_risk" ? "Marked as not a risk" : "Risk accepted"}
          {finding.issue?.triage_reason && <>: {finding.issue.triage_reason}</>}
          {finding.issue?.triage_expires_at && <> — until {new Date(finding.issue.triage_expires_at).toLocaleDateString()}</>}
          <Button onClick={() => runTriage("reopen")} disabled={busy}>Reopen</Button>
        </div>
      )}

      <div className="ds-issue-grid">
        <div className="ds-issue-main-col">
          <WhyRankedPanel factors={finding.scoring.risk_factors ?? []} riskScore={finding.scoring.risk_score} />

          <div className="ds-issue-section">
            <div className="ds-issue-label">{steps.length > 1 ? "How the input gets there" : "Location"}</div>
            <TaintStepper steps={steps} activeIndex={activeStep} onStepClick={setActiveStep} />
          </div>

          <div className="ds-issue-section">
            <CodeView code={finding.location.snippet || "(no snippet available)"} path={finding.location.path} />
          </div>

          <div className="ds-issue-section">
            <button type="button" className="ds-issue-explain-toggle" onClick={() => setExplanationOpen((v) => !v)} aria-expanded={explanationOpen}>
              What this means {mode === "novice" && <span className="ds-ai-tag">AI</span>} {explanationOpen ? "▾" : "▸"}
            </button>
            {explanationOpen && <p className="ds-issue-explain-text">{aiExplanation ?? finding.description}</p>}
          </div>
        </div>

        <aside className="ds-issue-sidebar">
          <div>
            <div className="ds-issue-label">Status</div>
            <SeverityBadge severity={finding.scoring.normalized_severity.toLowerCase() as "critical" | "high" | "medium" | "low" | "info"} reachable={finding.scoring.reachable !== false} />
            {finding.issue?.first_seen_at && <p className="ds-issue-meta">First seen {new Date(finding.issue.first_seen_at).toLocaleDateString()}</p>}
          </div>
          {mode === "expert" && (
            <div>
              <div className="ds-issue-label">Rule IDs</div>
              <ul className="ds-issue-rules">
                {Object.entries(finding.evidence.rule_ids).map(([tool, ids]) => (
                  <li key={tool}><code>{tool}</code>: {ids.join(", ")}</li>
                ))}
              </ul>
            </div>
          )}
          <div className="ds-issue-actions">
            <Button variant="primary" onClick={() => setTriageOpen("not_a_risk")} disabled={triageStatus !== "open"}>Mark as not a risk</Button>
            <Button onClick={() => setTriageOpen("accepted")} disabled={triageStatus !== "open"}>Accept risk until…</Button>
          </div>
          <div>
            <div className="ds-issue-label">History</div>
            <ul className="ds-issue-history">
              {(history ?? []).map((h, i) => (
                <li key={i}><span>{new Date(h.at).toLocaleDateString()}</span> {h.label}</li>
              ))}
            </ul>
          </div>
        </aside>
      </div>

      <Dialog open={triageOpen === "not_a_risk"} onOpenChange={(o) => !o && setTriageOpen(null)} title="Mark as not a risk" description="A reason is required, and this is written to the audit log.">
        <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={3} placeholder="Why isn't this a risk?" className="ds-issue-input" />
        <div style={{ marginTop: "1rem" }}>
          <Button variant="primary" disabled={!reason.trim() || busy} onClick={() => runTriage("not_a_risk")}>Confirm</Button>
        </div>
      </Dialog>

      <Dialog open={triageOpen === "accepted"} onOpenChange={(o) => !o && setTriageOpen(null)} title="Accept this risk" description="An expiry date is required — it reappears automatically once it passes. Written to the audit log.">
        <input type="date" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} className="ds-issue-input" />
        <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} placeholder="Optional note" className="ds-issue-input" style={{ marginTop: "0.5rem" }} />
        <div style={{ marginTop: "1rem" }}>
          <Button variant="primary" disabled={!expiresAt || busy} onClick={() => runTriage("accepted")}>Confirm</Button>
        </div>
      </Dialog>
    </div>
  );
}
