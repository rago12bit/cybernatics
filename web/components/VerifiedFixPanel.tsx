"use client";

import { Fragment, useEffect, useState } from "react";
import {
  ApiError,
  approveVerifiedFix,
  getVerifiedFix,
  rejectVerifiedFix,
  startVerifiedFix,
} from "@/lib/api";
import type { VerifiedFixStatus, VerifiedFixView } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./verified-fix-panel.css";

const STEP_LABEL: Record<string, string> = {
  rerun_rule: "The originating rule no longer matches",
  rerun_scanners: "No new issues from any scanner in changed files",
  run_tests: "Project tests",
};

const ENDED_REASON_LABEL: Record<string, string> = {
  overall_timeout: "Verification ran out of time overall",
  per_attempt_timeout: "One attempt ran out of time",
  max_attempts_exhausted: "Every attempt was rejected",
  approval_timeout: "Nobody reviewed this in time",
};

function attemptSummary(view: VerifiedFixView): string {
  const n = view.attempts;
  if (n <= 1) return "Took 1 attempt.";
  const failed = view.verification_record.slice(0, -1);
  const reasons = failed.map((a) => a.feedback).filter((f): f is string => Boolean(f));
  const first = reasons[0];
  return `Took ${n} attempts.${first ? ` The first attempt was rejected: ${first}` : ""}`;
}

function Diff({ patch }: { patch: string }) {
  return (
    <pre className="snippet diff ds-fix-diff" tabIndex={0} aria-label="Proposed patch">
      <code>
        {patch.split("\n").map((line, i, all) => (
          <Fragment key={i}>
            <span
              className={
                line.startsWith("+") ? "d-add" : line.startsWith("-") ? "d-del" : line.startsWith("@@") ? "d-hunk" : undefined
              }
            >
              {line}
            </span>
            {i < all.length - 1 ? "\n" : null}
          </Fragment>
        ))}
      </code>
    </pre>
  );
}

function VerificationRecord({ view }: { view: VerifiedFixView }) {
  const lastAttempt = view.verification_record[view.verification_record.length - 1];
  const steps = lastAttempt?.steps ?? [];
  return (
    <div className="ds-fix-section">
      <div className="ds-fix-label">Verification</div>
      <ul className="ds-fix-steps">
        {steps.map((s, i) => (
          <li key={i} className={s.passed ? "ds-fix-step-pass" : "ds-fix-step-fail"}>
            <span className="ds-fix-step-tag">{s.passed ? "Passed" : "Failed"}</span>
            <span>
              {STEP_LABEL[s.name] ?? s.name}
              {(!s.passed || s.name === "run_tests") && s.detail ? `: ${s.detail}` : ""}
            </span>
          </li>
        ))}
      </ul>
      {view.attempts > 0 && <p className="ds-fix-attempts">{attemptSummary(view)}</p>}
    </div>
  );
}

function statusLine(view: VerifiedFixView): string {
  switch (view.status) {
    case "running":
      return "Proposing and verifying a fix…";
    case "awaiting_approval":
      return "A verified patch is ready for review.";
    case "approved":
      return "Approved. Opening a pull request…";
    case "opened_pr":
      return "Pull request opened.";
    case "rejected":
      return "Rejected. No pull request was opened.";
    case "failed":
      return `No verified fix could be produced${view.ended_reason ? `: ${ENDED_REASON_LABEL[view.ended_reason] ?? view.ended_reason}` : ""}.`;
    case "inconclusive":
      return `Inconclusive${view.ended_reason ? `: ${ENDED_REASON_LABEL[view.ended_reason] ?? view.ended_reason}` : ""} — this is not evidence the fix is wrong, just that verification did not finish.`;
  }
}

export function VerifiedFixPanel({ assetId, issueId }: { assetId: string; issueId: string }) {
  const [view, setView] = useState<VerifiedFixView | null | undefined>(undefined); // undefined: loading
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function reload() {
    getVerifiedFix(assetId, issueId).then(setView, (e) => setError(e instanceof ApiError ? e.message : "Failed to load"));
  }
  useEffect(reload, [assetId, issueId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Poll while a run is actively in progress; a finished/awaiting run needs no polling.
  useEffect(() => {
    if (!view || view.status !== "running") return;
    const t = setInterval(reload, 4000);
    return () => clearInterval(t);
  }, [view]); // eslint-disable-line react-hooks/exhaustive-deps

  async function start() {
    setBusy(true);
    setError(null);
    try {
      await startVerifiedFix(assetId, issueId);
      reload();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not start the verified-fix agent");
    } finally {
      setBusy(false);
    }
  }

  async function decide(action: "approve" | "reject") {
    setBusy(true);
    setError(null);
    try {
      await (action === "approve" ? approveVerifiedFix : rejectVerifiedFix)(assetId, issueId);
      reload();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "That action failed");
    } finally {
      setBusy(false);
    }
  }

  if (view === undefined) return null; // first load: no flash of "start a fix" before we know

  if (view === null) {
    return (
      <div className="ds-fix-panel ds-fix-empty">
        <Button variant="primary" onClick={start} disabled={busy}>
          {busy ? "Starting…" : "Try a verified fix"}
        </Button>
        {error && <p className="ds-fix-error" role="alert">{error}</p>}
      </div>
    );
  }

  return (
    <div className="ds-fix-panel">
      <div className="ds-fix-head">
        <span className="ds-fix-title">Verified fix</span>
        <span className={`ds-fix-status ds-fix-status-${view.status}`}>{statusLine(view)}</span>
      </div>

      {view.verification_record.length > 0 && <VerificationRecord view={view} />}

      {view.latest_patch && (
        <div className="ds-fix-section">
          <div className="ds-fix-label">{view.latest_patch.confidence} confidence</div>
          <Diff patch={view.latest_patch.patch} />
          <p className="small muted">Written by AI and checked automatically. Review it before applying.</p>
        </div>
      )}

      {view.status === "awaiting_approval" && (
        <div className="ds-fix-actions">
          <Button onClick={() => decide("reject")} disabled={busy}>Reject</Button>
          <Button variant="primary" onClick={() => decide("approve")} disabled={busy}>
            {busy ? "Working…" : "Open pull request"}
          </Button>
        </div>
      )}

      {view.status === "opened_pr" && view.pr_url && (
        <p className="ds-fix-pr-link">
          Pull request opened: <a href={view.pr_url} target="_blank" rel="noreferrer">{view.pr_url}</a>
        </p>
      )}

      {(view.status === "rejected" || view.status === "failed" || view.status === "inconclusive") && (
        <Button onClick={start} disabled={busy}>{busy ? "Starting…" : "Try again"}</Button>
      )}

      {error && <p className="ds-fix-error" role="alert">{error}</p>}
    </div>
  );
}
