"use client";

import { useEffect, useState } from "react";
import { ApiError, getTriageAssessment, requestTriageAssessment } from "@/lib/api";
import type { TriageAssistantView } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./triage-assistant-panel.css";

const VERDICT_LABEL: Record<TriageAssistantView["verdict"], string> = {
  likely_real: "Likely real",
  likely_false_positive: "Likely false positive",
  unsure: "Unsure",
};

export function TriageAssistantPanel({ assetId, issueId }: { assetId: string; issueId: string }) {
  const [view, setView] = useState<TriageAssistantView | null | undefined>(undefined); // undefined: loading
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getTriageAssessment(assetId, issueId).then(setView, (e) => setError(e instanceof ApiError ? e.message : "Failed to load"));
  }, [assetId, issueId]);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      setView(await requestTriageAssessment(assetId, issueId));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not get a triage verdict");
    } finally {
      setBusy(false);
    }
  }

  if (view === undefined) return null; // first load: no flash before we know

  return (
    <div className="ds-triage-panel">
      <div className="ds-triage-head">
        <span className="ds-triage-title">Triage assistant</span>
        {view && (
          <span className={`ds-triage-verdict ds-triage-verdict-${view.verdict.replace(/_/g, "-")}`}>
            {VERDICT_LABEL[view.verdict]} · {view.confidence} confidence
          </span>
        )}
      </div>

      {view ? (
        <>
          <p className="ds-triage-rationale">{view.rationale}</p>
          {view.supporting_lines.length > 0 && (
            <p className="small muted">
              Based on line{view.supporting_lines.length > 1 ? "s" : ""} {view.supporting_lines.join(", ")}.
            </p>
          )}
          <p className="small muted">
            Advisory only -- this does not change the issue&apos;s status. A fresh verdict here will inform this
            asset&apos;s next scan.
          </p>
          <Button onClick={run} disabled={busy}>{busy ? "Asking…" : "Re-run"}</Button>
        </>
      ) : (
        <Button onClick={run} disabled={busy}>{busy ? "Asking…" : "Get a triage verdict"}</Button>
      )}

      {error && <p className="ds-triage-error" role="alert">{error}</p>}
    </div>
  );
}
