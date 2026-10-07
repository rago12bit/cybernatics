"use client";

import Link from "next/link";
import { useEffect, useId, useState, type ReactNode } from "react";
import {
  ApiError,
  getMe,
  getMyAssigned,
  getMyEngagements,
  setMyRole,
} from "@/lib/api";
import {
  ROLES,
  ROLE_HOME,
  dueWords,
  type AssignedIssue,
  type Me,
  type MyEngagement,
  type Role,
} from "@/lib/dashboard";
import { Button } from "@/design-system/primitives/Button";
import { DashboardScreen } from "../dashboard/DashboardScreen";
import { AppShell } from "../shell/AppShell";
import { UnitList } from "./UnitOverviewScreen";
import "../dashboard/dashboard.css";
import "./home.css";

/* Role-based homes (plan §48.2): leads land on a program dashboard, engineers on what is assigned
 * to them, testers on their engagements. Until user accounts carry roles (Week 75) each person
 * picks theirs. The shared token is nobody, so it keeps the plain scan page (`fallback`). */

export function RolePicker({
  current,
  onChosen,
}: {
  current: Role | null;
  onChosen: (m: Me) => void;
}) {
  const id = useId();
  const [role, setRole] = useState<Role | null>(current);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function save(e: React.FormEvent) {
    e.preventDefault();
    if (!role) return setError("Choose one.");
    setBusy(true);
    try {
      onChosen(await setMyRole(role));
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Could not save your choice.",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <form className="home-picker" onSubmit={save} aria-labelledby={`${id}-q`}>
      <h2 id={`${id}-q`}>What do you do here?</h2>
      <p className="dash-muted">
        It decides the page you land on. You can change it any time.
      </p>
      <fieldset>
        <legend className="sr-only">Your role</legend>
        {ROLES.map((r) => (
          <label key={r} className="home-choice">
            <input
              type="radio"
              name={`${id}-role`}
              value={r}
              checked={role === r}
              onChange={() => setRole(r)}
            />
            <span>
              <strong>{ROLE_HOME[r].title}</strong> — you land on{" "}
              {ROLE_HOME[r].lands}.
            </span>
          </label>
        ))}
      </fieldset>
      {error && (
        <p role="alert" className="dash-error">
          {error}
        </p>
      )}
      <Button type="submit" variant="primary" disabled={busy}>
        Save
      </Button>
    </form>
  );
}

function Assigned() {
  const [data, setData] = useState<{
    total: number;
    rows: AssignedIssue[];
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    getMyAssigned().then(setData, (e) =>
      setError(
        e instanceof ApiError ? e.message : "Could not load your issues.",
      ),
    );
  }, []);
  return (
    <section className="home-section" aria-labelledby="assigned-heading">
      <h1 id="assigned-heading">Assigned to you</h1>
      {error && (
        <p role="alert" className="dash-error">
          {error}
        </p>
      )}
      {!data && !error && <p role="status">Loading…</p>}
      {data && data.total === 0 && (
        <p className="dash-muted">Nothing is assigned to you.</p>
      )}
      {data && data.total > 0 && (
        <div className="dash-table-wrap">
          <table className="dash-table">
            <caption>
              {data.total} open issue{data.total === 1 ? "" : "s"}, the soonest
              SLA deadline first
              {data.rows.length < data.total
                ? ` (first ${data.rows.length} shown)`
                : ""}
            </caption>
            <thead>
              <tr>
                <th scope="col">Issue</th>
                <th scope="col">Project</th>
                <th scope="col">Priority</th>
                <th scope="col">SLA</th>
              </tr>
            </thead>
            <tbody>
              {data.rows.map((r) => (
                <tr key={r.issue_id}>
                  <th scope="row">
                    <Link
                      href={`/app/projects/${encodeURIComponent(r.project_id)}/issues/${encodeURIComponent(r.issue_id)}`}
                    >
                      {r.title}
                    </Link>
                  </th>
                  <td>{r.project}</td>
                  <td>{r.band}</td>
                  <td
                    className={
                      r.days_left !== null && r.days_left < 0
                        ? "home-late"
                        : undefined
                    }
                  >
                    {dueWords(r.days_left)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function Engagements() {
  const [rows, setRows] = useState<MyEngagement[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    getMyEngagements().then(setRows, (e) =>
      setError(
        e instanceof ApiError ? e.message : "Could not load your engagements.",
      ),
    );
  }, []);
  return (
    <section className="home-section" aria-labelledby="eng-heading">
      <h1 id="eng-heading">Your engagements</h1>
      {error && (
        <p role="alert" className="dash-error">
          {error}
        </p>
      )}
      {!rows && !error && <p role="status">Loading…</p>}
      {rows?.length === 0 && (
        <p className="dash-muted">
          No engagement names you as its lead or a tester yet. Engagements name
          people by their token&apos;s name or @handle.
        </p>
      )}
      {rows && rows.length > 0 && (
        <div className="dash-table-wrap">
          <table className="dash-table">
            <caption>Engagements you lead or test on, active first</caption>
            <thead>
              <tr>
                <th scope="col">Engagement</th>
                <th scope="col">Project</th>
                <th scope="col">You are</th>
                <th scope="col">Status</th>
                <th scope="col">Target end</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id}>
                  <th scope="row">
                    <Link href={`/app/engagements/${encodeURIComponent(e.id)}`}>
                      {e.name}
                    </Link>
                  </th>
                  <td>{e.project}</td>
                  <td>{e.as.join(" and ")}</td>
                  <td>{e.status}</td>
                  <td className={e.overdue ? "home-late" : undefined}>
                    {e.target_end_at ? e.target_end_at.slice(0, 10) : "—"}
                    {e.overdue ? " (overdue)" : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export function RoleHome({ fallback }: { fallback: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [changing, setChanging] = useState(false);
  useEffect(() => {
    getMe().then(setMe, () => setMe(null));
  }, []);

  if (!me || !me.person) return <>{fallback}</>;
  if (!me.role || changing) {
    return (
      <AppShell crumbs={[{ label: "Home" }]}>
        <div className="dash">
          <span className="eyebrow">Home</span>
          <h1>Welcome</h1>
          <RolePicker
            current={me.role}
            onChosen={(m) => {
              setMe(m);
              setChanging(false);
            }}
          />
        </div>
        {!me.role && <div className="home-below">{fallback}</div>}
      </AppShell>
    );
  }
  const role = me.role;
  return (
    <AppShell crumbs={[{ label: "Home" }]}>
      <div className="dash">
        <div className="home-head">
          <div>
            <span className="eyebrow">Home · {ROLE_HOME[role].title}</span>
            <p className="dash-muted home-why">
              You land on {ROLE_HOME[role].lands}.{" "}
              <button
                type="button"
                className="home-link-button"
                onClick={() => setChanging(true)}
              >
                Change role
              </button>
            </p>
          </div>
          <nav aria-label="Elsewhere" className="dash-row">
            <Link href="/app/scan" className="ds-button">
              Scan a codebase
            </Link>
            <Link href="/app/projects" className="ds-button">
              Projects
            </Link>
            <Link href="/app/dashboards" className="ds-button">
              Dashboards
            </Link>
            <Link href="/app/portfolios" className="ds-button">
              Business units
            </Link>
          </nav>
        </div>
        {role === "lead" && (
          <>
            <DashboardScreen embedded />
            <UnitList heading="Business units" level={2} />
          </>
        )}
        {role === "engineer" && <Assigned />}
        {role === "tester" && <Engagements />}
      </div>
    </AppShell>
  );
}
