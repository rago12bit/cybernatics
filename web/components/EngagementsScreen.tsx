"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { ApiError, createEngagement, listEngagements } from "@/lib/api";
import type { Engagement } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import { EngagementForm } from "./EngagementForm";
import { STATUS_WORD, dateRange } from "./EngagementScreen";
import "./engagement.css";

/** A project's assessments (plan §43.1): pen tests and audits, each with its scope and people. */
export function EngagementsScreen({ assetId }: { assetId: string }) {
  const router = useRouter();
  const [items, setItems] = useState<Engagement[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(() => {
    listEngagements(assetId).then(setItems, (e) => setError(e instanceof ApiError ? e.message : "Could not load engagements."));
  }, [assetId]);
  useEffect(load, [load]);

  if (error) return <p role="alert" className="ds-eng-error">{error}</p>;
  if (!items) return <p role="status">Loading engagements…</p>;

  return (
    <div className="ds-eng">
      <h1 className="ds-eng-title">Engagements</h1>
      <p className="ds-eng-help">
        A pen test or an audit of this project: its scope, who tests it, an optional OWASP checklist, the findings, and the report
        written when it closes.
      </p>
      {!creating && <Button variant="primary" onClick={() => setCreating(true)}>New engagement</Button>}
      {creating && (
        <section className="ds-eng-panel" aria-label="New engagement">
          <h2>New engagement</h2>
          <EngagementForm
            submitLabel="Create engagement"
            onCancel={() => setCreating(false)}
            onSubmit={async (body) => {
              const e = await createEngagement(assetId, body);
              router.push(`/app/engagements/${e.id}`);
            }}
          />
        </section>
      )}
      {items.length === 0 ? (
        <p className="ds-eng-empty">No engagements yet.</p>
      ) : (
        <ul className="ds-eng-list">
          {items.map((e) => (
            <li key={e.id}>
              <Link href={`/app/engagements/${e.id}`} className="ds-eng-list-name">{e.name}</Link>
              <span className={`ds-eng-status ds-eng-status-${e.status}`}>{STATUS_WORD[e.status]}</span>
              <span className="ds-eng-meta">
                {dateRange(e)}
                {e.lead && ` · lead ${e.lead}`}
                {e.checklist && ` · ${e.checklist.name}: ${e.checklist.done} of ${e.checklist.total} done`}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
