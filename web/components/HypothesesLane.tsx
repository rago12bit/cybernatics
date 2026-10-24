"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, dismissHypothesis, generateHypotheses, listHypotheses, promoteHypothesis } from "@/lib/api";
import type { Hypothesis } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import { Loading } from "@/design-system/primitives/Loading";
import "./hypotheses-lane.css";

function HypothesisCard({
  h,
  assetId,
  busy,
  onPromoted,
  onDismissed,
  onError,
}: {
  h: Hypothesis;
  assetId: string;
  busy: boolean;
  onPromoted: (issueId: string) => void;
  onDismissed: () => void;
  onError: (message: string) => void;
}) {
  const [working, setWorking] = useState(false);

  async function promote() {
    setWorking(true);
    try {
      const { issue_id } = await promoteHypothesis(assetId, h.id);
      onPromoted(issue_id);
    } catch (e) {
      onError(e instanceof ApiError ? e.message : "Could not promote this hypothesis");
    } finally {
      setWorking(false);
    }
  }

  async function dismiss() {
    setWorking(true);
    try {
      await dismissHypothesis(assetId, h.id);
      onDismissed();
    } catch (e) {
      onError(e instanceof ApiError ? e.message : "Could not dismiss this hypothesis");
    } finally {
      setWorking(false);
    }
  }

  return (
    <li className="ds-hyp-card">
      <div className="ds-hyp-head">
        <code className="ds-hyp-route">
          {h.route_method || "(any method)"} {h.route_path || "(no path)"}
        </code>
        <span className="ds-hyp-location">{h.file}:{h.line}</span>
        <span className="ds-hyp-confidence">{h.confidence} confidence</span>
      </div>
      <p className="ds-hyp-evidence">{h.evidence}</p>
      {h.suggested_check && (
        <p className="ds-hyp-check">
          <strong>Suggested check:</strong> {h.suggested_check}
        </p>
      )}
      {h.status === "open" ? (
        <div className="ds-hyp-actions">
          <Button onClick={dismiss} disabled={busy || working}>Dismiss</Button>
          <Button variant="primary" onClick={promote} disabled={busy || working}>
            {working ? "Working…" : "Confirm — create an issue"}
          </Button>
        </div>
      ) : h.status === "promoted" && h.promoted_issue_id ? (
        <p className="ds-hyp-status">
          Confirmed — <Link href={`/app/projects/${assetId}/issues/${h.promoted_issue_id}`}>view the issue</Link>
        </p>
      ) : (
        <p className="ds-hyp-status">Dismissed</p>
      )}
    </li>
  );
}

export function HypothesesLane({ assetId }: { assetId: string }) {
  const [items, setItems] = useState<Hypothesis[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);

  function reload() {
    listHypotheses(assetId).then(setItems, (e) => setError(e instanceof ApiError ? e.message : "Failed to load"));
  }
  useEffect(reload, [assetId]); // eslint-disable-line react-hooks/exhaustive-deps

  async function generate() {
    setGenerating(true);
    setError(null);
    try {
      await generateHypotheses(assetId);
      reload();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not generate hypotheses");
    } finally {
      setGenerating(false);
    }
  }

  const open = (items ?? []).filter((h) => h.status === "open");
  const decided = (items ?? []).filter((h) => h.status !== "open");

  return (
    <div className="ds-hyp">
      <div className="ds-hyp-intro">
        <p className="small muted">
          Flaws pattern-based scanning can&apos;t express -- e.g. a route missing the authorization check its
          siblings have. Off by default, never counted in the risk score, and never shown in the main issue list
          until you confirm one.
        </p>
        <Button variant="primary" onClick={generate} disabled={generating}>
          {generating ? "Generating…" : "Generate"}
        </Button>
      </div>

      {error && <p className="ds-hyp-error" role="alert">{error}</p>}

      {items === null ? (
        <Loading />
      ) : items.length === 0 ? (
        <p className="ds-hyp-empty">
          Nothing here yet. Click Generate to check this project&apos;s latest scan for routes that may be
          missing an authorization check.
        </p>
      ) : (
        <>
          {open.length > 0 && (
            <ul className="ds-hyp-list">
              {open.map((h) => (
                <HypothesisCard
                  key={h.id}
                  h={h}
                  assetId={assetId}
                  busy={generating}
                  onPromoted={reload}
                  onDismissed={reload}
                  onError={setError}
                />
              ))}
            </ul>
          )}
          {decided.length > 0 && (
            <details className="ds-hyp-decided">
              <summary>{decided.length} already reviewed</summary>
              <ul className="ds-hyp-list">
                {decided.map((h) => (
                  <HypothesisCard
                    key={h.id}
                    h={h}
                    assetId={assetId}
                    busy={generating}
                    onPromoted={reload}
                    onDismissed={reload}
                    onError={setError}
                  />
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </div>
  );
}
