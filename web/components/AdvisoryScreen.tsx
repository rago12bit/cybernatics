"use client";

import Link from "next/link";
import { useCallback, useEffect, useId, useState } from "react";
import { ApiError, createAdvisoryIssues, getAdvisory } from "@/lib/api";
import type { AdvisoryImpact, AdvisoryIssuesCreated, AdvisoryUse } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import { Severity, ago } from "./AdvisoriesScreen";
import "./advisories.css";

/** Plan §55.5, the advisory impact view (journey J7): where an affected version is, which projects'
 * code imports the library, who owns them, how exposed they are, the fix, and Issues in one click.
 * "Not imported by application code" is as far as it goes: the screen never says code is
 * unreachable. */

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const SHOWN = 5;
const EXPOSURE = { internet: "Internet", internal: "Internal", unset: "Not set" } as const;

export function impactSentence(a: AdvisoryImpact): string {
  const c = a.summary_counts;
  if (c.projects === 0) return "No project's current SBOM has an affected version any more.";
  const where = `An affected version is in ${plural(c.projects, "project")}${c.portfolios ? ` across ${plural(c.portfolios, "business unit")}` : ""}.`;
  const imported = c.imported_by_app
    ? ` ${c.imported_by_app} of them import${c.imported_by_app === 1 ? "s" : ""} it from application code.`
    : " None is known to import it from application code.";
  const unsure = c.uncertain ? ` For ${c.uncertain}, the version could not be compared.` : "";
  return where + imported + unsure;
}

export function fixLine(uses: AdvisoryUse[]): string {
  if (!uses.length) return "";
  const byLib = new Map<string, Set<string>>();
  let none = 0;
  for (const u of uses) {
    if (!u.fixed_version) { none += 1; continue; }
    byLib.set(u.library, (byLib.get(u.library) ?? new Set()).add(u.fixed_version));
  }
  const parts = [...byLib].map(([lib, v]) => `upgrade ${lib.split(":").at(-1)} to ${[...v].join(" or ")}`);
  const fix = parts.length ? `Fix: ${parts.join("; ")}.` : "No fixed version is listed.";
  return none && parts.length ? `${fix} No fixed version is listed for ${plural(none, "use")}.` : fix;
}

function Imported({ u }: { u: AdvisoryUse }) {
  if (u.reachable === true) return <span className="ds-adv-yes" title={u.reachable_reason}>Yes</span>;
  if (u.reachable === false) return <span title={u.reachable_reason}>Not by application code</span>;
  return <span className="ds-adv-meta" title={u.reachable_reason || "Reachability is analysed for Python and JavaScript projects scanned by Bulwark"}>Can&apos;t tell</span>;
}

export function AdvisoryScreen({ vulnKey }: { vulnKey: string }) {
  const fid = useId();
  const [a, setA] = useState<AdvisoryImpact | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [all, setAll] = useState(false);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<AdvisoryIssuesCreated | null>(null);

  const load = useCallback(() => {
    getAdvisory(vulnKey).then(setA, (e) => setError(e instanceof ApiError && e.status === 404 ? "This advisory does not affect any of your projects." : "Could not load the advisory."));
  }, [vulnKey]);
  useEffect(load, [load]);

  async function create() {
    setBusy(true);
    setError(null);
    try {
      setDone(await createAdvisoryIssues(vulnKey));
      load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not create the Issues.");
    } finally {
      setBusy(false);
    }
  }

  if (!a) return <div className="ds-adv">{error ? <p role="alert" className="ds-adv-error">{error}</p> : <p>Loading…</p>}</div>;
  const uses = a.uses;
  const shown = all ? uses : uses.slice(0, SHOWN);
  const rest = uses.slice(SHOWN);
  const projects = a.summary_counts.projects - a.summary_counts.uncertain;
  return (
    <div className="ds-adv">
      <header className="ds-adv-head">
        <div className="ds-adv-row-top">
          <h1 className="ds-adv-title">{a.vuln_key}</h1>
          <Severity value={a.severity} />
          {a.cvss !== null && <span className="ds-adv-meta" title={a.cvss_vector}>CVSS {a.cvss.toFixed(1)}</span>}
          {a.kev && <span className="ds-adv-kev" title={a.kev.name}>Known exploited (CISA KEV since {a.kev.date_added}{a.kev.due_date ? `, due ${a.kev.due_date}` : ""})</span>}
          {a.malicious && <span className="ds-adv-kev">Malicious package</span>}
        </div>
        <p className="ds-adv-lede">{a.summary}</p>
        <p className="ds-adv-meta">
          {a.ids.join(", ")}{a.aliases.length ? ` · also ${a.aliases.join(", ")}` : ""}
          {a.published ? ` · published ${new Date(a.published).toLocaleDateString()}` : ""} · first seen here {ago(a.first_seen_at)}
        </p>
      </header>

      <section aria-labelledby={`${fid}-impact`} className="ds-adv-box">
        <h2 id={`${fid}-impact`} className="ds-adv-verdict">{impactSentence(a)}</h2>
        {uses.length > 0 && (
          <table className="ds-adv-table">
            <caption className="ds-adv-meta">Projects with an affected version, those importing it from application code first</caption>
            <thead>
              <tr>
                <th scope="col">Project</th><th scope="col">Version</th><th scope="col">Imported by application code</th>
                <th scope="col">Owner</th><th scope="col">Exposure</th><th scope="col">Issue</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((u) => (
                <tr key={`${u.project_id}-${u.library}-${u.version}`}>
                  <th scope="row" data-label="Project">
                    <Link href={`/app/projects/${u.project_id}`}>{u.project}</Link>
                    <span className="ds-adv-meta"> · {u.library}</span>
                  </th>
                  <td data-label="Version" className="ds-adv-nowrap">
                    <code>{u.version}</code>{!u.certain && <span className="ds-adv-meta"> (could not be compared)</span>}
                    {u.fixed_version && <span className="ds-adv-meta"> → {u.fixed_version}</span>}
                  </td>
                  <td data-label="Imported"><Imported u={u} /></td>
                  <td data-label="Owner">{u.owner ?? <Link href={`/app/projects/${u.project_id}`} className="ds-adv-meta">Set an owner</Link>}</td>
                  <td data-label="Exposure" className="ds-adv-nowrap">{EXPOSURE[u.exposure]}</td>
                  <td data-label="Issue">
                    {u.issues.length
                      ? u.issues.map((i) => <Link key={i.id} href={`/app/projects/${u.project_id}/issues/${i.id}`}>{i.state === "fixed" ? "Fixed" : "Open"}</Link>)
                      : <span className="ds-adv-meta">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {rest.length > 0 && !all && (
          <p className="ds-adv-more">
            {plural(rest.length, "more use")}
            {rest.every((u) => u.reachable !== true) ? ", none imported by application code" : ""}{" "}
            <Button onClick={() => setAll(true)}>Show all</Button>
          </p>
        )}
        <p className="ds-adv-fix">{fixLine(uses)}</p>
        {uses.length > 0 && (
          <div className="ds-adv-actions">
            <Button variant="primary" disabled={busy || projects === 0} onClick={create}>
              {busy ? "Working…" : a.state === "issues"
                ? "Bring the Issues up to date"
                : `Create Issues in ${plural(projects, "project")}, grouped under ${a.vuln_key}`}
            </Button>
            <span className="ds-adv-meta">Each project&apos;s Issues form one group; projects with ticket settings get one ticket; owners are assigned. They close when an SBOM no longer has an affected version.</span>
          </div>
        )}
        {done && (
          <p role="status" className="ds-adv-done-msg">
            {plural(done.issues, "Issue")} in {plural(done.projects, "project")}; {plural(done.tickets, "ticket")} filed or updated.
            {done.ticket_errors.length ? ` Tickets failed: ${done.ticket_errors.join("; ")}.` : ""}
          </p>
        )}
        {error && <p role="alert" className="ds-adv-error">{error}</p>}
      </section>

      {a.no_longer_affected.length > 0 && (
        <details className="ds-adv-box">
          <summary>{plural(a.no_longer_affected.length, "use")} no longer affected</summary>
          <ul className="ds-adv-plain">
            {a.no_longer_affected.map((u) => (
              <li key={`${u.project_id}-${u.library}-${u.version}`}>
                <Link href={`/app/projects/${u.project_id}`}>{u.project}</Link> · {u.library} <code>{u.version}</code>
                <span className="ds-adv-meta"> · not in its SBOM since {u.resolved_at ? new Date(u.resolved_at).toLocaleDateString() : "—"}</span>
              </li>
            ))}
          </ul>
        </details>
      )}

      {a.details && (
        <section aria-labelledby={`${fid}-details`} className="ds-adv-box">
          <h2 id={`${fid}-details`}>Details</h2>
          <p className="ds-adv-details">{a.details}</p>
          {a.references.length > 0 && (
            <ul className="ds-adv-plain">
              {a.references.filter((r) => /^https?:\/\//.test(r)).slice(0, 12).map((r) => (
                <li key={r}><a href={r} rel="noopener noreferrer nofollow" target="_blank">{r}</a></li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  );
}
