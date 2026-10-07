"use client";

import { createColumnHelper, flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, bulkTriageIssues, createIssueView, getAssetOverview, listIssues, type IssuesQuery, type OpenSlaState } from "@/lib/api";
import { SLA_MARK, SLA_WORD, slaDetail, slaSentence } from "@/lib/sla";
import type { Finding, PriorityBand, Severity, TriageStatus } from "@/lib/types";
import { SEVERITIES } from "@/lib/types";
import { SeverityIcon } from "@/design-system/severity";
import { Button } from "@/design-system/primitives/Button";
import { Dialog } from "@/design-system/primitives/Dialog";
import { RiskAcceptanceRequest } from "@/components/RiskAcceptanceRequest";
import { useMode } from "@/design-system/mode";
import { shortLocation } from "@/lib/format";
import { legacyToQuery } from "@/lib/issues";
import { setIssueNavList } from "@/lib/issue-nav";
import "./issues-table.css";

const ROW_HEIGHT_COMFORTABLE = 56;
const ROW_HEIGHT_COMPACT = 40;

function defaultQuery(): IssuesQuery {
  return { severity: [], category: "", triage: [], sla: [], priority: [], sort: "risk" };
}

const columnHelper = createColumnHelper<Finding>();

/** Plan §31: TanStack Table for the column model (selection, severity, title/location, triage,
 * rule id), TanStack Virtual for rendering only the rows on screen — real usage of both named
 * tools, not just a hand-rolled scroller. Server-side pagination (up to 200 issues per fetch, see
 * lib/api.ts's listIssues) still bounds each request; the virtualization is what lets the table
 * itself stay smooth once that page is on screen, exactly the plan's own "without jank" framing. */
export function IssuesTable({ assetId }: { assetId: string }) {
  const { mode } = useMode();
  const [q, setQ] = useState<IssuesQuery>(defaultQuery());
  const [page, setPage] = useState<{ total: number; items: Finding[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [label, setLabel] = useState<string | null>(null);
  const [saveOpen, setSaveOpen] = useState(false);
  const [viewName, setViewName] = useState("");
  const [triageOpen, setTriageOpen] = useState<"not_a_risk" | "accepted" | null>(null);
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const parentRef = useRef<HTMLDivElement>(null);

  const reload = useCallback(() => {
    listIssues(assetId, q).then(
      (p) => { setPage(p); setError(null); },
      (e) => setError(e instanceof ApiError ? e.message : "Failed to load issues"),
    );
  }, [assetId, q]);
  useEffect(reload, [reload]);

  const items = useMemo(() => page?.items ?? [], [page]);

  // Record this page's order so j/k on the issue detail page (opened from a row below) walks the
  // same list that's actually on screen here, not a second, independently-sorted fetch.
  useEffect(() => {
    setIssueNavList(assetId, items.map((f) => f.issue?.id).filter((id): id is string => !!id));
  }, [assetId, items]);

  const columns = useMemo(
    () => [
      columnHelper.display({
        id: "select",
        header: () => <span className="sr-only-ds">Select</span>,
        cell: (ctx) => (
          <input
            type="checkbox"
            checked={selected.has(ctx.row.original.id)}
            onChange={() => toggleRow(ctx.row.original.id)}
            aria-label={`Select ${ctx.row.original.title}`}
          />
        ),
      }),
      columnHelper.accessor((f) => f.scoring.normalized_severity, {
        id: "severity",
        header: "Severity",
        cell: (ctx) => <SeverityIcon severity={ctx.getValue().toLowerCase() as "critical" | "high" | "medium" | "low" | "info"} />,
      }),
      columnHelper.display({
        id: "priority",
        header: "Priority",
        cell: (ctx) => {
          const p = ctx.row.original.issue?.priority;
          if (!p || p.score == null || !p.band) return null;
          const why = p.factors.map((f) => f.text).join(" · ");
          return (
            <span className={`ds-issue-prio ds-issue-prio-${p.band}`} title={why || undefined}>
              {p.band} <span className="ds-issue-prio-score">{p.score}</span>
            </span>
          );
        },
      }),
      columnHelper.accessor("title", {
        header: "Issue",
        cell: (ctx) => {
          const f = ctx.row.original;
          return (
            <div className="ds-issue-main">
              <Link href={`/app/projects/${assetId}/issues/${f.issue?.id ?? ""}`} className="ds-issue-title">{f.title}</Link>
              {mode === "novice" && <code className="ds-issue-loc">{shortLocation(f)}</code>}
            </div>
          );
        },
      }),
      columnHelper.display({
        id: "triage",
        header: "Status",
        cell: (ctx) => {
          const t = ctx.row.original.issue?.triage_status;
          return t && t !== "open" ? <span className="ds-issue-triage-tag">{t === "not_a_risk" ? "Not a risk" : "Accepted"}</span> : null;
        },
      }),
      columnHelper.display({
        id: "sla",
        header: "SLA",
        cell: (ctx) => {
          const sla = ctx.row.original.issue?.sla;
          if (!sla || sla.state === "none") return null;
          return (
            <span className={`ds-issue-sla ds-issue-sla-${sla.state}`} title={slaSentence(sla)}>
              <span aria-hidden="true">{SLA_MARK[sla.state]} </span>
              {SLA_WORD[sla.state]}
              {slaDetail(sla) && <span className="ds-issue-sla-detail"> · {slaDetail(sla)}</span>}
            </span>
          );
        },
      }),
      columnHelper.display({
        id: "rule",
        header: "Rule",
        cell: (ctx) => (mode === "expert" ? <code className="ds-issue-rule">{Object.values(ctx.row.original.evidence.rule_ids)[0]?.[0] ?? ""}</code> : null),
      }),
      // eslint-disable-next-line react-hooks/exhaustive-deps
    ],
    [selected, mode, assetId],
  );

  const table = useReactTable({ data: items, columns, getCoreRowModel: getCoreRowModel() });
  const rows = table.getRowModel().rows;
  const rowHeight = mode === "expert" ? ROW_HEIGHT_COMPACT : ROW_HEIGHT_COMFORTABLE;
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    overscan: 10,
  });

  function toggleSeverity(s: Severity) {
    setQ((cur) => ({ ...cur, severity: cur.severity.includes(s) ? cur.severity.filter((x) => x !== s) : [...cur.severity, s] }));
  }
  function toggleTriage(t: TriageStatus) {
    setQ((cur) => ({ ...cur, triage: cur.triage.includes(t) ? cur.triage.filter((x) => x !== t) : [...cur.triage, t] }));
  }
  function togglePriority(b: PriorityBand) {
    setQ((cur) => {
      const now = cur.priority ?? [];
      return { ...cur, priority: now.includes(b) ? now.filter((x) => x !== b) : [...now, b] };
    });
  }
  function toggleSla(s: OpenSlaState) {
    setQ((cur) => {
      const now = cur.sla ?? [];
      return { ...cur, sla: now.includes(s) ? now.filter((x) => x !== s) : [...now, s] };
    });
  }
  function toggleRow(id: string) {
    setSelected((cur) => {
      const next = new Set(cur);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }
  const selectedIssueIds = useMemo(
    () => items.filter((f) => selected.has(f.id) && f.issue).map((f) => f.issue!.id),
    [items, selected],
  );

  async function runTriage(action: "not_a_risk" | "accepted" | "reopen") {
    setBusy(true);
    try {
      const body = action === "not_a_risk" ? { action, reason } : action === "accepted" ? { action, reason, expires_at: expiresAt } : { action };
      await bulkTriageIssues(assetId, selectedIssueIds, body);
      setSelected(new Set());
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

  // Saved views live on the server now, on the Issues list across every project; this table saves
  // its filters there as a query for this project.
  useEffect(() => {
    getAssetOverview(assetId).then((o) => setLabel(o?.asset?.label ?? null), () => setLabel(null));
  }, [assetId]);

  async function saveView(name: string) {
    if (!label) return;
    try {
      const v = await createIssueView(legacyToQuery({ assetId, name, query: q }, label));
      setNotice(`Saved “${v.name}”. Find it under Saved views on the Issues list.`);
      setSaveOpen(false);
      setViewName("");
    } catch (e) {
      setError(e instanceof ApiError ? ((e.data as { message?: string } | undefined)?.message ?? e.message) : "Could not save the view.");
    }
  }

  return (
    <div className="ds-issues">
      <div className="ds-issues-toolbar">
        <div className="ds-issues-chips" role="group" aria-label="Severity">
          {SEVERITIES.map((s) => (
            <button key={s} type="button" className={q.severity.includes(s) ? "ds-chip active" : "ds-chip"} onClick={() => toggleSeverity(s)}>
              <SeverityIcon severity={s.toLowerCase() as "critical" | "high" | "medium" | "low" | "info"} size={14} />
              {s}
            </button>
          ))}
        </div>
        <div className="ds-issues-chips" role="group" aria-label="Triage status">
          {(["not_a_risk", "accepted"] as TriageStatus[]).map((t) => (
            <button key={t} type="button" className={q.triage.includes(t) ? "ds-chip active" : "ds-chip"} onClick={() => toggleTriage(t)}>
              {t === "not_a_risk" ? "Not a risk" : "Accepted"}
            </button>
          ))}
        </div>
        <div className="ds-issues-chips" role="group" aria-label="Priority">
          {(["P1", "P2", "P3", "P4"] as PriorityBand[]).map((b) => (
            <button key={b} type="button" aria-pressed={(q.priority ?? []).includes(b)} className={(q.priority ?? []).includes(b) ? "ds-chip active" : "ds-chip"} onClick={() => togglePriority(b)}>
              {b}
            </button>
          ))}
        </div>
        <div className="ds-issues-chips" role="group" aria-label="SLA">
          {(["breached", "due_soon", "on_track"] as OpenSlaState[]).map((s) => (
            <button key={s} type="button" aria-pressed={(q.sla ?? []).includes(s)} className={(q.sla ?? []).includes(s) ? "ds-chip active" : "ds-chip"} onClick={() => toggleSla(s)}>
              <span aria-hidden="true">{SLA_MARK[s]}</span> {SLA_WORD[s]}
            </button>
          ))}
        </div>
        <select value={q.sort} onChange={(e) => setQ((cur) => ({ ...cur, sort: e.target.value as IssuesQuery["sort"] }))} aria-label="Sort">
          <option value="risk">Sort: priority</option>
          <option value="severity">Sort: severity</option>
          <option value="path">Sort: file path</option>
        </select>
        <div className="ds-issues-spacer" />
        <Button onClick={() => setSaveOpen(true)}>Save this view</Button>
      </div>

      {label && (
        <p className="ds-issues-across">
          <Link href={`/app/issues?q=${encodeURIComponent(`project:${/^[^\s",:]+$/.test(label) ? label : `"${label}"`}`)}`}>
            This project on the Issues list
          </Link>{" "}
          <span className="ds-issues-across-note">with saved views, queries and changes across pages</span>
        </p>
      )}

      {selected.size > 0 && (
        <div className="ds-bulkbar" role="toolbar" aria-label="Bulk triage">
          <span>{selected.size} selected</span>
          <Button variant="primary" onClick={() => setTriageOpen("not_a_risk")}>Mark not a risk</Button>
          <Button onClick={() => setTriageOpen("accepted")}>Request risk acceptance</Button>
          <Button onClick={() => runTriage("reopen")} disabled={busy}>Reopen</Button>
          <Button onClick={() => setSelected(new Set())}>Clear</Button>
        </div>
      )}

      {notice && <p className="ds-issues-notice" role="status">{notice}</p>}
      {error && <p className="ds-issues-error" role="alert">{error}</p>}
      {!error && page && page.total === 0 && <p className="ds-issues-empty">Nothing here. Try a different filter, or check the triaged-away issues above.</p>}

      {!error && page && page.total > 0 && (
        // Standard ARIA grid pattern for a virtualized, div-based table (no real <table>: TanStack
        // Virtual's absolute-positioned rows don't work inside one). Without this, the rows are
        // invisible to a screen reader as tabular data -- just an unstructured list of text.
        <div className="ds-issues-table-wrap" role="table" aria-label="Issues" aria-rowcount={rows.length + 1}>
          <div className="ds-issues-headrow" role="row" aria-rowindex={1}>
            {table.getHeaderGroups()[0]?.headers.map((h) => (
              <div key={h.id} role="columnheader" className={`ds-issues-headcell col-${h.column.id}`}>
                {flexRender(h.column.columnDef.header, h.getContext())}
              </div>
            ))}
          </div>
          <div ref={parentRef} className="ds-issues-scroll" role="rowgroup" style={{ height: "min(70vh, 640px)" }}>
            <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
              {virtualizer.getVirtualItems().map((vi) => {
                const row = rows[vi.index];
                if (!row) return null;
                return (
                  <div
                    key={row.id}
                    role="row"
                    aria-rowindex={vi.index + 2} // +1 for the header row, +1 because aria-rowindex is 1-based
                    className={`ds-issue-row${mode === "expert" ? " compact" : ""}`}
                    style={{ position: "absolute", top: 0, left: 0, width: "100%", height: vi.size, transform: `translateY(${vi.start}px)` }}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <div key={cell.id} role="cell" className={`ds-issues-cell col-${cell.column.id}`}>
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </div>
                    ))}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      <Dialog open={saveOpen} onOpenChange={setSaveOpen} title="Save this view" description="Name these filters to come back to them, from any device. Views are kept on the Issues list.">
        <input type="text" value={viewName} onChange={(e) => setViewName(e.target.value)} placeholder="e.g. Critical, unreachable-excluded" className="ds-palette-input" />
        <div style={{ marginTop: "1rem", display: "flex", gap: "0.5rem" }}>
          <Button
            variant="primary"
            disabled={!viewName.trim() || !label}
            onClick={() => {
              void saveView(viewName.trim());
            }}
          >
            Save
          </Button>
        </div>
      </Dialog>

      <Dialog
        open={triageOpen === "not_a_risk"}
        onOpenChange={(o) => !o && setTriageOpen(null)}
        title="Mark as not a risk"
        description="A reason is required, and this is written to the audit log."
      >
        <label htmlFor="bulk-triage-reason" className="ds-palette-label">Reason</label>
        <textarea id="bulk-triage-reason" value={reason} onChange={(e) => setReason(e.target.value)} rows={3} placeholder="Why isn't this a risk?" className="ds-palette-input" style={{ width: "100%", resize: "vertical" }} />
        <div style={{ marginTop: "1rem" }}>
          <Button variant="primary" disabled={!reason.trim() || busy} onClick={() => runTriage("not_a_risk")}>Confirm</Button>
        </div>
      </Dialog>

      <Dialog
        open={triageOpen === "accepted"}
        onOpenChange={(o) => !o && setTriageOpen(null)}
        title={`Request risk acceptance for ${selectedIssueIds.length} issue${selectedIssueIds.length === 1 ? "" : "s"}`}
        description="Someone other than you approves it; until then the issues stay open. Every step is in the audit log."
      >
        <RiskAcceptanceRequest
          assetId={assetId}
          issueIds={selectedIssueIds}
          onCancel={() => setTriageOpen(null)}
          onDone={() => { setTriageOpen(null); setSelected(new Set()); setNotice("Request sent. The issues stay open until someone else approves."); reload(); }}
        />
      </Dialog>
    </div>
  );
}
