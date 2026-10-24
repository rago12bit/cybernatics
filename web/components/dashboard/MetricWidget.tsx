"use client";

import Link from "next/link";
import { useEffect, useId, useLayoutEffect, useState, type ReactNode } from "react";
import { ApiError, getMetric } from "@/lib/api";
import { ENTRY, describeFilters, filterParams, titleOf, type MetricResult, type Widget } from "@/lib/dashboard";
import { present, type Table } from "@/lib/dashboard-present";
import { Button } from "@/design-system/primitives/Button";
import { Dialog } from "@/design-system/primitives/Dialog";
import { ChartView } from "./charts";
import { formatDateTime } from "@/lib/format";
import { Loading } from "@/design-system/primitives/Loading";

/* One widget: its title opens the metric's written definition; its numbers open the Issues behind
 * them; a chart can be read as a table. Records how long it took to draw once its data arrived
 * (`window.__bulwarkWidgetTimings`), against the 300 ms budget (plan §60). */

declare global {
  interface Window {
    __bulwarkWidgetTimings?: { widget: string; metric: string; ms: number }[];
  }
}

function TableView({ t }: { t: Table }) {
  return (
    <div className="dash-table-wrap">
      <table className="dash-table">
        <caption>{t.caption}</caption>
        <thead>
          <tr>{t.head.map((h) => <th key={h} scope="col">{h}</th>)}</tr>
        </thead>
        <tbody>
          {t.rows.length === 0 && (
            <tr><td colSpan={t.head.length} className="dash-muted">Nothing to list.</td></tr>
          )}
          {t.rows.map((r, i) => (
            <tr key={i}>
              {r.map((cell, j) => {
                const body = cell.href ? <Link href={cell.href}>{cell.text}</Link> : cell.text;
                return j === 0 ? (
                  <th key={j} scope="row" className={cell.num ? "num" : undefined}>{body}</th>
                ) : (
                  <td key={j} className={cell.num ? "num" : undefined}>{body}</td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function MetricWidget({
  widget,
  names = {},
  actions,
}: {
  widget: Widget;
  names?: Record<string, string>;
  actions?: ReactNode;
}) {
  const headingId = useId();
  const [data, setData] = useState<MetricResult | null>(null);
  const [arrived, setArrived] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [asTable, setAsTable] = useState(false);
  const [defining, setDefining] = useState(false);
  const entry = ENTRY[widget.metric];
  const filterKey = JSON.stringify(widget.filters ?? {});

  useEffect(() => {
    const ctl = new AbortController();
    setError(null);
    getMetric(widget.metric, filterParams(widget.filters), ctl.signal).then(
      (r) => {
        setArrived(performance.now());
        setData(r);
      },
      (e) => {
        if (ctl.signal.aborted) return;
        setError(e instanceof ApiError ? e.message : "Could not load this widget.");
      },
    );
    return () => ctl.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- filterKey stands for widget.filters
  }, [widget.metric, filterKey]);

  // Committed to the DOM: how long the widget took to draw once its data arrived.
  useLayoutEffect(() => {
    if (!data || !arrived) return;
    const ms = Math.round(performance.now() - arrived);
    (window.__bulwarkWidgetTimings ??= []).push({ widget: widget.id, metric: widget.metric, ms });
  }, [data, arrived, widget.id, widget.metric]);

  const shown = data ? present(data, widget.filters) : null;
  const filters = describeFilters(widget.filters, names);
  const title = titleOf(widget);
  const chart = entry?.chart && shown && shown.charts.length > 0;

  return (
    <section className="dash-widget" aria-labelledby={headingId}>
      <header className="dash-widget-head">
        <h2 className="dash-widget-title" id={headingId}>
          <Dialog
            title={title}
            description="How this number is defined"
            open={defining}
            onOpenChange={setDefining}
            trigger={
              <button type="button" className="dash-title-button" aria-label={`${title}: what this measures`}>
                {title}
              </button>
            }
          >
            <p>{data?.definition ?? "Loading the definition…"}</p>
            {data?.notes.map((n) => <p key={n} className="dash-muted">{n}</p>)}
            {data?.period && <p className="dash-muted">Period: {data.period[0]} to {data.period[1]}.</p>}
            {data && (
              <p className="dash-muted">
                Computed {formatDateTime(data.generated_at)}
                {data.pending_refresh > 0 && `; ${data.pending_refresh} project${data.pending_refresh === 1 ? " is" : "s are"} still being refreshed`}. Every definition is also in docs/metrics.md.
              </p>
            )}
            <Button type="button" onClick={() => setDefining(false)}>Close</Button>
          </Dialog>
        </h2>
        <div className="dash-widget-tools">
          {chart && (
            <Button type="button" aria-pressed={asTable} onClick={() => setAsTable((v) => !v)}
              aria-label={`View as table: ${title}`}>
              View as table
            </Button>
          )}
          {actions}
        </div>
      </header>
      {filters && <p className="dash-filters">{filters}</p>}
      <div className="dash-widget-body">
        {error && <p role="alert" className="dash-error">{error}</p>}
        {!error && !shown && <Loading />}
        {shown && (
          <>
            <p className="dash-headline">
              {shown.headline.href ? <Link href={shown.headline.href}>{shown.headline.text}</Link> : shown.headline.text}
            </p>
            {shown.detail.length > 0 && (
              <ul className="dash-detail">
                {shown.detail.map((d) => <li key={d.text}>{d.href ? <Link href={d.href}>{d.text}</Link> : d.text}</li>)}
              </ul>
            )}
            {data && data.pending_refresh > 0 && (
              <p className="dash-muted dash-small">Updating: {data.pending_refresh} project{data.pending_refresh === 1 ? "" : "s"} waiting to refresh.</p>
            )}
            {shown.empty ? (
              <p className="dash-muted">{shown.empty}</p>
            ) : chart && !asTable ? (
              shown.charts.map((c) => (
                <div key={c.label} className="dash-chart-block">
                  <p className="dash-chart-label" aria-hidden="true">{c.label}</p>
                  <ChartView c={c} />
                </div>
              ))
            ) : (
              shown.tables.map((t) => <TableView key={t.caption} t={t} />)
            )}
          </>
        )}
      </div>
    </section>
  );
}
