"use client";

import Link from "next/link";
import { useEffect, useId, useState } from "react";
import { ApiError, getAdvisoryFeeds, listAdvisories } from "@/lib/api";
import type { AdvisoryFeeds, AdvisorySummary } from "@/lib/types";
import "./advisories.css";

/** Plan §46.2 and journey J7, "the new-CVE morning": every vulnerability affecting the
 * organization's projects now, the newest first, each linking to its impact view. */

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const FILTERS = [
  { value: "", label: "All" },
  { value: "new", label: "Not acted on" },
  { value: "issues", label: "Issues created" },
] as const;

export function ago(iso: string | null, now = Date.now()): string {
  if (!iso) return "never";
  const mins = Math.round((now - new Date(iso).getTime()) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `${hours} h ago`;
  return `${Math.round(hours / 24)} days ago`;
}

export function feedsLine(f: AdvisoryFeeds, now = Date.now()): string {
  if (!f.feeds.length) return "No advisory data yet: the first update runs on the worker's schedule.";
  const osv = f.feeds.filter((x) => x.source.startsWith("osv:"));
  const newest = osv.map((x) => x.last_success_at).filter(Boolean).sort().at(-1) ?? null;
  const failing = f.feeds.filter((x) => x.last_error).map((x) => x.source.replace("osv:", "OSV "));
  return `${f.advisories.toLocaleString()} advisories (OSV updated ${ago(newest, now)}), ${f.kev_entries.toLocaleString()} known exploited.`
    + (failing.length ? ` Last update failed for ${failing.join(", ")}.` : "");
}

export function Severity({ value }: { value: string }) {
  return <span className={`ds-adv-sev ds-adv-sev-${value.toLowerCase()}`}>{value.charAt(0) + value.slice(1).toLowerCase()}</span>;
}

export function AdvisoriesScreen() {
  const fid = useId();
  const [rows, setRows] = useState<AdvisorySummary[] | null>(null);
  const [feeds, setFeeds] = useState<AdvisoryFeeds | null>(null);
  const [state, setState] = useState("");
  const [kev, setKev] = useState(false);
  const [q, setQ] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getAdvisoryFeeds().then(setFeeds, () => setFeeds(null));
  }, []);
  useEffect(() => {
    const t = setTimeout(() => {
      listAdvisories({ state: state || undefined, kev, q: q.trim() || undefined }).then(
        (r) => { setRows(Array.isArray(r) ? r : []); setError(null); },
        (e) => setError(e instanceof ApiError ? e.message : "Could not load advisories."),
      );
    }, q ? 200 : 0);
    return () => clearTimeout(t);
  }, [state, kev, q]);

  return (
    <div className="ds-adv">
      <h1>Advisories</h1>
      <p className="ds-adv-meta">
        Vulnerabilities affecting a version in your projects&apos; current SBOMs, from OSV (GitHub, PyPI, Go and
        malicious-package reports), with CISA&apos;s known-exploited list. {feeds ? feedsLine(feeds) : ""}
      </p>
      <div className="ds-adv-filters">
        <fieldset className="ds-adv-tabs">
          <legend className="ds-adv-meta">Show</legend>
          {FILTERS.map((f) => (
            <label key={f.value} className={state === f.value ? "ds-adv-tab-on" : undefined}>
              <input type="radio" name={`${fid}-state`} value={f.value} checked={state === f.value} onChange={() => setState(f.value)} />
              {f.label}
            </label>
          ))}
        </fieldset>
        <label className="ds-adv-check">
          <input type="checkbox" checked={kev} onChange={(e) => setKev(e.target.checked)} /> Known exploited only
        </label>
        <div className="ds-adv-search">
          <label htmlFor={`${fid}-q`} className="ds-adv-meta">Search</label>
          <input id={`${fid}-q`} className="ds-adv-q" type="search" value={q} placeholder="CVE, library or words" onChange={(e) => setQ(e.target.value)} />
        </div>
      </div>
      {error && <p role="alert" className="ds-adv-error">{error}</p>}
      {rows && rows.length === 0 && (
        <p>{state || kev || q ? "Nothing matches." : "No advisory affects a version in your projects' current SBOMs."}</p>
      )}
      {rows && rows.length > 0 && (
        <ul className="ds-adv-list">
          {rows.map((r) => (
            <li key={r.vuln_key} className={r.kev ? "ds-adv-kevrow" : undefined}>
              <div className="ds-adv-row-top">
                <Link href={`/app/advisories/${encodeURIComponent(r.vuln_key)}`} className="ds-adv-key">{r.vuln_key}</Link>
                <Severity value={r.severity} />
                {r.kev && <span className="ds-adv-kev">Known exploited</span>}
                {r.malicious && <span className="ds-adv-kev">Malicious package</span>}
                {r.state === "issues" && <span className="ds-adv-done">Issues created</span>}
                <span className="ds-adv-meta ds-adv-when">first seen {ago(r.first_seen_at)}</span>
              </div>
              <p className="ds-adv-summary">{r.summary}</p>
              <p className="ds-adv-meta">
                {r.libraries.join(", ")} · in {plural(r.projects, "project")}
                {r.internet_facing ? `, ${r.internet_facing} internet-facing` : ""}
                {r.imported_by_app ? `, ${r.imported_by_app} importing it from application code` : ""}
                {r.uncertain ? `, ${r.uncertain} could not be compared` : ""}
              </p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
