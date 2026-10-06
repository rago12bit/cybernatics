"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import {
  ApiError, confirmRuleRun, deleteRule, dismissRuleRun, listRuleRuns, listRuleTemplates, listRules, setRuleEnabled, testRule,
} from "@/lib/api";
import type { Rule, RuleDryRun, RuleRun, RuleTemplate } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./automation.css";

/** Plan §45 and the IA's "Automation: rules, templates, run history". Held runs come first: a rule
 * that would act on more issues than its threshold waits here for an Admin. Writing a rule, testing
 * it and deciding a held run need the `rules:write` scope; the server says no otherwise. */

export const RUN_WORD: Record<RuleRun["status"], string> = {
  running: "Running",
  applied: "Applied",
  held: "Waiting for confirmation",
  confirmed: "Confirmed and applied",
  dismissed: "Dismissed",
  depth_limited: "Stopped: chain too deep",
  failed: "Failed",
};

const when = (iso: string) => new Date(iso).toLocaleString();

export function outcomeSummary(run: RuleRun): string {
  if (run.status === "held") return `Would act on ${run.subject_ids.length} issue${run.subject_ids.length === 1 ? "" : "s"}.`;
  if (run.error && !run.results.length) return run.error;
  const changed = run.results.filter((r) => r.outcome === "changed").length;
  const failed = run.results.filter((r) => r.outcome === "failed");
  const skipped = run.results.filter((r) => r.outcome === "skipped");
  const parts = [`${changed} change${changed === 1 ? "" : "s"}`];
  if (failed.length) parts.push(`${failed.length} failed (${failed[0]?.detail ?? "no reason given"})`);
  if (skipped.length) parts.push(`${skipped.length} skipped (${skipped[0]?.detail ?? ""})`);
  return parts.join(", ") + ".";
}

export function automationVerdict(rules: Rule[], held: RuleRun[]): string {
  if (held.length) return `${held.length} run${held.length === 1 ? " is" : "s are"} waiting for an Admin to confirm.`;
  const on = rules.filter((r) => r.enabled).length;
  if (!rules.length) return "No rules yet: nothing runs on its own.";
  return `${on} of ${rules.length} rule${rules.length === 1 ? "" : "s"} on. Nothing is waiting.`;
}

function Subjects({ run }: { run: RuleRun }) {
  return (
    <ul className="ds-au-subjects">
      {run.subjects.map((x) => (
        <li key={x.id}>
          {x.asset_id ? (
            <Link href={`/app/projects/${x.asset_id}/issues/${x.id}`}>{x.title ?? x.text}</Link>
          ) : (
            x.text
          )}
          {x.severity && <span className="ds-au-meta"> · {x.severity}{x.priority_band ? `, ${x.priority_band}` : ""} · {x.project}</span>}
        </li>
      ))}
      {run.subject_ids.length > run.subjects.length && (
        <li className="ds-au-meta">…and {run.subject_ids.length - run.subjects.length} more</li>
      )}
    </ul>
  );
}

export function HeldRun({ run, onDecided }: { run: RuleRun; onDecided: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function decide(fn: (id: string) => Promise<RuleRun>) {
    setBusy(true);
    setError(null);
    try {
      await fn(run.id);
      onDecided();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "That did not work.");
      setBusy(false);
    }
  }
  return (
    <li className="ds-au-held">
      <p className="ds-au-held-head">
        <strong>{run.rule_name}</strong> would act on {run.subject_ids.length} issues from {run.cause_label}.
      </p>
      <p className="ds-au-meta">Held {when(run.created_at)}: more than the rule&apos;s threshold, so nothing has changed yet.</p>
      <Subjects run={run} />
      {error && <p role="alert" className="ds-au-error">{error}</p>}
      <div className="ds-au-actions">
        <Button variant="primary" disabled={busy} onClick={() => decide(confirmRuleRun)}>Apply to all {run.subject_ids.length}</Button>
        <Button disabled={busy} onClick={() => decide(dismissRuleRun)}>Dismiss</Button>
      </div>
    </li>
  );
}

function RuleCard({ rule, onChanged }: { rule: Rule; onChanged: () => void }) {
  const [dry, setDry] = useState<RuleDryRun | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function act(fn: () => Promise<unknown>, after?: () => void) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      after?.();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "That did not work.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <li className={`ds-au-rule${rule.enabled ? "" : " ds-au-off"}`}>
      <div className="ds-au-rule-head">
        <Link href={`/app/automation/${rule.id}`} className="ds-au-rule-name">{rule.name}</Link>
        <span className="ds-au-state">{rule.enabled ? "On" : "Off"}</span>
        <span className="ds-au-meta">{rule.project_name ?? "Every project"} · v{rule.version}</span>
      </div>
      <ul className="ds-au-summary" aria-label={`What ${rule.name} does`}>
        {rule.summary.map((line, i) => {
          const [word, ...rest] = line.split(" ");
          return <li key={i}><span className="ds-au-word">{word}</span> <code className="ds-au-cond">{rest.join(" ")}</code></li>;
        })}
      </ul>
      <p className="ds-au-meta">
        {rule.last_fired_at ? `Last acted ${when(rule.last_fired_at)}` : "Has not acted yet"} · confirms over {rule.confirm_over} issues
      </p>
      {dry && (
        <div className="ds-au-dry" role="status">
          <p>{dry.sentence}</p>
          <p className="ds-au-meta">{dry.note}</p>
        </div>
      )}
      {error && <p role="alert" className="ds-au-error">{error}</p>}
      <div className="ds-au-actions">
        <Button disabled={busy} onClick={() => act(async () => setDry(await testRule(rule.id)))}>Test this rule</Button>
        <Button disabled={busy} onClick={() => act(() => setRuleEnabled(rule.id, !rule.enabled), onChanged)}>
          {rule.enabled ? "Turn off" : "Turn on"}
        </Button>
        <Button
          disabled={busy}
          onClick={() => {
            if (window.confirm(`Delete “${rule.name}”? Its run history stays.`)) act(() => deleteRule(rule.id), onChanged);
          }}
        >
          Delete
        </Button>
      </div>
    </li>
  );
}

export function AutomationScreen() {
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [held, setHeld] = useState<RuleRun[]>([]);
  const [recent, setRecent] = useState<RuleRun[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [templates, setTemplates] = useState<RuleTemplate[]>([]);

  useEffect(() => {
    listRuleTemplates().then((t) => setTemplates(Array.isArray(t) ? t : []), () => setTemplates([]));
  }, []);

  const load = useCallback(() => {
    Promise.all([listRules(), listRuleRuns({ status: "held" }), listRuleRuns({ limit: 30 })]).then(
      ([r, h, all]) => {
        setRules(Array.isArray(r) ? r : []);
        setHeld(Array.isArray(h) ? h : []);
        setRecent(Array.isArray(all) ? all.filter((x) => x.status !== "held") : []);
      },
      (e) => setError(e instanceof ApiError ? e.message : "Could not load the rules."),
    );
  }, []);
  useEffect(load, [load]);

  if (error) return <p role="alert" className="ds-au-error">{error}</p>;
  if (!rules) return <p role="status">Loading rules…</p>;
  return (
    <div className="ds-au">
      <div className="ds-au-top">
        <h1>Automation</h1>
        <Link href="/app/automation/new" className="ds-au-new">New rule</Link>
      </div>
      <p className="ds-au-verdict">{automationVerdict(rules, held)}</p>

      {held.length > 0 && (
        <section aria-labelledby="au-held">
          <h2 id="au-held">Waiting for confirmation</h2>
          <ul className="ds-au-list">{held.map((r) => <HeldRun key={r.id} run={r} onDecided={load} />)}</ul>
        </section>
      )}

      <section aria-labelledby="au-rules">
        <h2 id="au-rules">Rules</h2>
        {rules.length === 0 ? (
          <p>Start from a template below, or write one with “New rule”.</p>
        ) : (
          <ul className="ds-au-list">{rules.map((r) => <RuleCard key={r.id} rule={r} onChanged={load} />)}</ul>
        )}
      </section>

      {templates.length > 0 && (
        <section aria-labelledby="au-gallery">
          <h2 id="au-gallery">Start from a template</h2>
          <ul className="ds-au-gallery">
            {templates.map((t) => (
              <li key={t.key}>
                <Link href={`/app/automation/new?template=${encodeURIComponent(t.key)}`}>{t.name}</Link>
                <span className="ds-au-meta">{t.description}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section aria-labelledby="au-history">
        <h2 id="au-history">Run history</h2>
        {recent.length === 0 ? (
          <p>No rule has run yet.</p>
        ) : (
          <table className="ds-au-table">
            <thead>
              <tr><th scope="col">When</th><th scope="col">Rule</th><th scope="col">Because of</th><th scope="col">Result</th></tr>
            </thead>
            <tbody>
              {recent.map((r) => (
                <tr key={r.id}>
                  <td>{when(r.created_at)}</td>
                  <td>{r.rule_name}{r.depth > 0 ? <span className="ds-au-meta"> · chain {r.depth}</span> : null}</td>
                  <td>{r.cause_label}</td>
                  <td>
                    <span className={`ds-au-run ds-au-run-${r.status}`}>{RUN_WORD[r.status]}</span>{" "}
                    <span className="ds-au-meta">{outcomeSummary(r)}</span>
                    {r.subjects.length > 0 && (
                      <details>
                        <summary>{r.subject_ids.length} {r.subjects[0]?.asset_id ? "issue" : "project"}{r.subject_ids.length === 1 ? "" : "s"}</summary>
                        <Subjects run={r} />
                      </details>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
