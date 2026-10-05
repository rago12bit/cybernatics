"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
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
import { getIssueNavList } from "@/lib/issue-nav";
import { VerifiedFixPanel } from "@/components/VerifiedFixPanel";
import { TriageAssistantPanel } from "@/components/TriageAssistantPanel";
import { ManualFindingPanel } from "@/components/ManualFindingPanel";
import { CopilotPanel } from "@/components/CopilotPanel";
import { SLA_MARK, slaSentence } from "@/lib/sla";
import "./issue-detail.css";

const isTyping = (t: EventTarget | null) => t instanceof HTMLElement && /^(INPUT|SELECT|TEXTAREA)$/.test(t.tagName);

export function IssueDetail({ assetId, issueId }: { assetId: string; issueId: string }) {
  const router = useRouter();
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

  // Default the stepper to the sink -- the code view should open on the dangerous call itself
  // (plan §28.3's own mockup), not step 1, whenever a real multi-hop path was found.
  useEffect(() => {
    if (!finding) return;
    const path = finding.taint_path ?? []; // a Finding persisted before this field existed has none
    const sinkIdx = path.length > 0 ? Math.max(0, path.findIndex((s) => s.is_sink)) : 0;
    setActiveStep(sinkIdx);
  }, [finding]);

  // j/k (plan §30.1, J3): move to the next/previous issue in whatever order the issues table showed
  // when this page was opened from it (lib/issue-nav.ts) -- the same list, not a second fetch that
  // could sort differently and desync (the bug the old scan report's FindingsTable.tsx hit once).
  // A direct link or a reload has no recorded list, so j/k simply does nothing rather than guessing.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (triageOpen || isTyping(e.target) || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key !== "j" && e.key !== "k") return;
      const list = getIssueNavList(assetId);
      const at = list.indexOf(issueId);
      if (at === -1) return;
      const next = list[at + (e.key === "j" ? 1 : -1)];
      if (next) router.push(`/app/projects/${assetId}/issues/${next}`);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [assetId, issueId, triageOpen, router]);

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
  if (!finding) {
    return (
      <div className="ds-issue" role="status" aria-busy="true">
        <span className="sr-only">Loading issue…</span>
        <div className="ds-issue-topline"><span className="sk sk-m" /></div>
        <div className="ds-issue-grid">
          <div className="ds-issue-main-col skeleton-list">
            <span className="sk sk-l" style={{ height: "1.6rem" }} />
            <span className="sk sk-row" />
            <span className="sk sk-row" />
            <span className="sk sk-l" />
          </div>
          <aside className="ds-issue-sidebar skeleton-list">
            <span className="sk sk-m" />
            <span className="sk sk-s" />
            <span className="sk sk-row" />
          </aside>
        </div>
      </div>
    );
  }

  // The taint-path stepper (plan §20.3, §28.3): core/taint/'s real engine (Week 37/38) attaches a
  // concrete, multi-hop source-to-sink path to a Finding when it found one. When it didn't (no
  // taint-confirmed path for this finding -- most findings today, since taint analysis only covers
  // Python/JS/TS/Go SAST sinks reachable from a detected HTTP entrypoint), the finding's own
  // location is the one real step shown -- never an invented intermediate hop either way.
  const taintPath = finding.taint_path ?? []; // a Finding persisted before this field existed has none
  const steps: TaintStep[] =
    taintPath.length > 0
      ? taintPath.map((s) => ({ path: s.path, line: s.line, label: s.description, isSink: s.is_sink }))
      : [{ path: finding.location.path, line: finding.location.start_line, label: "Where this happens", isSink: true }];
  const activeStepData = steps[Math.min(activeStep, steps.length - 1)];
  const activeSnippet = taintPath.length > 0 ? taintPath[Math.min(activeStep, steps.length - 1)]?.snippet : finding.location.snippet;
  const triageStatus = finding.issue?.triage_status ?? "open";

  return (
    <div className="ds-issue">
      <div className="ds-issue-topline">
        <Link href={`/app/projects/${assetId}/issues`}>← Issues</Link>
        <code>{finding.id}</code>
        <h1 className="ds-issue-topline-title">{finding.title}</h1>
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
          {finding.issue?.triage_expires_at && (
            <>
              {" "}
              — until <time dateTime={finding.issue.triage_expires_at}>{new Date(finding.issue.triage_expires_at).toLocaleDateString()}</time>
            </>
          )}
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
            <CodeView code={activeSnippet || "(no snippet available)"} path={activeStepData?.path ?? finding.location.path} highlightLine={activeStepData?.line} />
          </div>

          <div className="ds-issue-section">
            <button type="button" className="ds-issue-explain-toggle" onClick={() => setExplanationOpen((v) => !v)} aria-expanded={explanationOpen}>
              What this means {mode === "novice" && <span className="ds-ai-tag">AI</span>} {explanationOpen ? "▾" : "▸"}
            </button>
            {explanationOpen && <p className="ds-issue-explain-text">{aiExplanation ?? finding.description}</p>}
          </div>

          <ManualFindingPanel assetId={assetId} issueId={issueId} />

          {triageStatus === "open" && (
            <div className="ds-issue-section">
              <TriageAssistantPanel assetId={assetId} issueId={issueId} />
            </div>
          )}

          {triageStatus === "open" && (
            <div className="ds-issue-section">
              <VerifiedFixPanel assetId={assetId} issueId={issueId} />
            </div>
          )}
        </div>

        <aside className="ds-issue-sidebar">
          <div>
            <div className="ds-issue-label">Status</div>
            <SeverityBadge severity={finding.scoring.normalized_severity.toLowerCase() as "critical" | "high" | "medium" | "low" | "info"} reachable={finding.scoring.reachable !== false} />
            {finding.issue?.first_seen_at && (
              <p className="ds-issue-meta">
                First seen <time dateTime={finding.issue.first_seen_at}>{new Date(finding.issue.first_seen_at).toLocaleDateString()}</time>
              </p>
            )}
            {finding.issue?.sla && finding.issue.sla.state !== "none" && (
              <p className={`ds-issue-meta ds-issue-sla-line ds-issue-sla-${finding.issue.sla.state}`}>
                <span aria-hidden="true">{SLA_MARK[finding.issue.sla.state]} </span>
                SLA: {slaSentence(finding.issue.sla)}
                {finding.issue.sla.due_at && finding.issue.sla.state !== "met" && finding.issue.sla.state !== "missed" && (
                  <> (due <time dateTime={finding.issue.sla.due_at}>{new Date(finding.issue.sla.due_at).toLocaleDateString()}</time>)</>
                )}
              </p>
            )}
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
                <li key={i}><time dateTime={h.at}>{new Date(h.at).toLocaleDateString()}</time> {h.label}</li>
              ))}
            </ul>
          </div>
        </aside>
      </div>

      <Dialog open={triageOpen === "not_a_risk"} onOpenChange={(o) => !o && setTriageOpen(null)} title="Mark as not a risk" description="A reason is required, and this is written to the audit log.">
        <label htmlFor="triage-reason" className="ds-issue-label">Reason</label>
        <textarea id="triage-reason" value={reason} onChange={(e) => setReason(e.target.value)} rows={3} placeholder="Why isn't this a risk?" className="ds-issue-input" />
        <div style={{ marginTop: "1rem" }}>
          <Button variant="primary" disabled={!reason.trim() || busy} onClick={() => runTriage("not_a_risk")}>Confirm</Button>
        </div>
      </Dialog>

      <Dialog open={triageOpen === "accepted"} onOpenChange={(o) => !o && setTriageOpen(null)} title="Accept this risk" description="An expiry date is required — it reappears automatically once it passes. Written to the audit log.">
        <label htmlFor="triage-expires" className="ds-issue-label">Expires</label>
        <input id="triage-expires" type="date" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} className="ds-issue-input" />
        <label htmlFor="triage-note" className="ds-issue-label" style={{ marginTop: "0.5rem" }}>Note (optional)</label>
        <textarea id="triage-note" value={reason} onChange={(e) => setReason(e.target.value)} rows={2} placeholder="Optional note" className="ds-issue-input" />
        <div style={{ marginTop: "1rem" }}>
          <Button variant="primary" disabled={!expiresAt || busy} onClick={() => runTriage("accepted")}>Confirm</Button>
        </div>
      </Dialog>

      <CopilotPanel assetId={assetId} context={{ context_kind: "issue", context_id: issueId }} />
    </div>
  );
}
