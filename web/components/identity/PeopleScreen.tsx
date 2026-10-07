"use client";

import { useCallback, useEffect, useId, useMemo, useState, type FormEvent } from "react";
import { ApiError, createUser, listAssets, listPortfolios, listUsers, removeRoleOverride, setRoleOverride, updateUser } from "@/lib/api";
import { ORG_ROLES, OVERRIDE_ROLES, roleLabel, type OrgRole, type OverrideRole, type UserView } from "@/lib/identity";
import type { AssetSummary, Portfolio } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import { Dialog } from "@/design-system/primitives/Dialog";
import "./identity.css";

/* People and access (Week 75): who is in the organization, their role, the higher roles they
 * have on business units or projects, and turning someone off -- which ends their sessions and
 * revokes their tokens at once. People the identity provider manages over SCIM say so. */

function message(e: unknown, fallback: string): string {
  if (e instanceof ApiError) return (e.data as { message?: string } | undefined)?.message ?? e.message;
  return fallback;
}

function day(iso: string | null): string {
  return iso ? iso.slice(0, 10) : "never";
}

export function PeopleScreen() {
  const id = useId();
  const [people, setPeople] = useState<UserView[] | null>(null);
  const [projects, setProjects] = useState<AssetSummary[]>([]);
  const [units, setUnits] = useState<Portfolio[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [said, setSaid] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [confirmOff, setConfirmOff] = useState<UserView | null>(null);

  const load = useCallback(() => {
    listUsers().then((p) => { setPeople(p); setError(null); }, (e) => setError(message(e, "Could not load people.")));
  }, []);
  useEffect(() => {
    load();
    listAssets().then(setProjects, () => setProjects([]));
    listPortfolios().then(setUnits, () => setUnits([]));
  }, [load]);

  const names = useMemo(() => ({
    ...Object.fromEntries(projects.map((p) => [p.id, p.label])),
    ...Object.fromEntries(units.map((u) => [u.id, u.name])),
  }), [projects, units]);

  const replace = (u: UserView) => setPeople((cur) => cur?.map((x) => (x.id === u.id ? u : x)) ?? null);

  async function change(u: UserView, body: { role?: OrgRole; active?: boolean }, sentence: string) {
    setError(null);
    try { replace(await updateUser(u.id, body)); setSaid(sentence); }
    catch (e) { setError(message(e, "Could not save.")); }
  }

  if (error && !people) return <p role="alert" className="idn-error">{error}</p>;
  if (!people) return <p role="status">Loading people…</p>;
  return (
    <div className="idn">
      <div className="idn-bar">
        <p className="idn-muted">{people.filter((p) => p.active).length} active of {people.length}. Roles: {ORG_ROLES.map(([r, l, d]) => <span key={r} className="idn-role-hint"><strong>{l}</strong> — {d}. </span>)}</p>
        <Button type="button" variant="primary" onClick={() => setAdding(true)}>Add a person</Button>
      </div>
      <p role="status" className="idn-said">{said}</p>
      {error && <p role="alert" className="idn-error">{error}</p>}
      <div className="idn-scroll" tabIndex={0} role="region" aria-label="People">
        <table className="idn-table">
          <caption className="sr-only">People in this organization</caption>
          <thead>
            <tr><th scope="col">Person</th><th scope="col">Organization role</th><th scope="col">Higher roles</th><th scope="col">Last sign-in</th><th scope="col">Status</th></tr>
          </thead>
          <tbody>
            {people.map((u) => (
              <tr key={u.id} className={u.active ? undefined : "off"}>
                <th scope="row">
                  <span className="idn-name">{u.name}</span>
                  <span className="idn-email">{u.email}</span>
                  {u.source === "scim" && <span className="idn-tag">from your identity provider</span>}
                </th>
                <td>
                  <label className="sr-only" htmlFor={`${id}-r-${u.id}`}>Organization role of {u.name}</label>
                  <select id={`${id}-r-${u.id}`} value={u.role} disabled={!u.active}
                    onChange={(e) => change(u, { role: e.target.value as OrgRole }, `${u.name} is now ${roleLabel(e.target.value)}.`)}>
                    {ORG_ROLES.map(([r, l]) => <option key={r} value={r}>{l}</option>)}
                  </select>
                </td>
                <td>
                  {u.roles.length === 0 ? <span className="idn-muted">None</span> : (
                    <ul className="idn-overrides">
                      {u.roles.map((o) => <li key={o.id}>{roleLabel(o.role)} on {o.target_type === "portfolio" ? "unit" : "project"} <strong>{names[o.target_id] ?? "(gone)"}</strong></li>)}
                    </ul>
                  )}
                  <button type="button" className="idn-link" onClick={() => setOpen(u.id)} aria-label={`Change higher roles of ${u.name}`}>Change</button>
                </td>
                <td>{day(u.last_login_at)}</td>
                <td>
                  {u.deprovisioned_at ? <span className="idn-muted">Removed by your identity provider</span>
                    : u.active ? <Button type="button" onClick={() => setConfirmOff(u)} aria-label={`Turn off ${u.name}`}>Turn off</Button>
                    : <Button type="button" onClick={() => change(u, { active: true }, `${u.name} can sign in again.`)} aria-label={`Turn on ${u.name}`}>Turn on</Button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <AddPerson open={adding} onClose={() => setAdding(false)} onAdded={(u) => { setAdding(false); setPeople((cur) => [...(cur ?? []), u]); setSaid(`Added ${u.email}. They can sign in through your identity provider.`); }} />
      <Overrides person={people.find((p) => p.id === open) ?? null} projects={projects} units={units} names={names}
        onClose={() => setOpen(null)} onChanged={(u, s) => { replace(u); setSaid(s); }} />
      <Dialog open={confirmOff !== null} onOpenChange={(o) => !o && setConfirmOff(null)} title={`Turn off ${confirmOff?.name ?? ""}?`}
        description="They are signed out everywhere now, and every API token they made stops working. Their Issues, notes and history stay.">
        <div className="idn-actions">
          <Button type="button" variant="primary" onClick={() => { const u = confirmOff!; setConfirmOff(null); void change(u, { active: false }, `${u.name} is turned off; their sessions and tokens no longer work.`); }}>Turn off</Button>
          <Button type="button" onClick={() => setConfirmOff(null)}>Cancel</Button>
        </div>
      </Dialog>
    </div>
  );
}

function AddPerson({ open, onClose, onAdded }: { open: boolean; onClose: () => void; onAdded: (u: UserView) => void }) {
  const id = useId();
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<OrgRole>("member");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try { onAdded(await createUser({ email: email.trim(), name: name.trim() || undefined, role })); setEmail(""); setName(""); }
    catch (err) { setError(message(err, "Could not add them.")); }
    finally { setBusy(false); }
  }
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()} title="Add a person" description="They sign in through your organization's identity provider with this email.">
      <form onSubmit={submit} className="idn-form">
        <label htmlFor={`${id}-e`}>Email</label>
        <input id={`${id}-e`} type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        <label htmlFor={`${id}-n`}>Name (optional)</label>
        <input id={`${id}-n`} value={name} onChange={(e) => setName(e.target.value)} />
        <label htmlFor={`${id}-r`}>Organization role</label>
        <select id={`${id}-r`} value={role} onChange={(e) => setRole(e.target.value as OrgRole)}>
          {ORG_ROLES.map(([r, l]) => <option key={r} value={r}>{l}</option>)}
        </select>
        {error && <p role="alert" className="idn-error">{error}</p>}
        <div className="idn-actions">
          <Button type="submit" variant="primary" disabled={busy || !email.trim()}>Add</Button>
          <Button type="button" onClick={onClose}>Cancel</Button>
        </div>
      </form>
    </Dialog>
  );
}

function Overrides({ person, projects, units, names, onClose, onChanged }: {
  person: UserView | null; projects: AssetSummary[]; units: Portfolio[]; names: Record<string, string>;
  onClose: () => void; onChanged: (u: UserView, sentence: string) => void;
}) {
  const id = useId();
  const [kind, setKind] = useState<"project" | "portfolio">("project");
  const [target, setTarget] = useState("");
  const [role, setRole] = useState<OverrideRole>("member");
  const [error, setError] = useState<string | null>(null);
  if (!person) return null;
  const targets = kind === "project" ? projects.map((p) => [p.id, p.label] as const) : units.map((u) => [u.id, u.name] as const);
  async function add(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const u = await setRoleOverride(person!.id, { target_type: kind, target_id: target, role });
      onChanged(u, `${person!.name} is ${roleLabel(role)} on ${names[target] ?? "it"}.`);
      setTarget("");
    } catch (err) { setError(message(err, "Could not save.")); }
  }
  async function remove(overrideId: string, label: string) {
    setError(null);
    try { onChanged(await removeRoleOverride(person!.id, overrideId), `Removed ${person!.name}'s role on ${label}.`); }
    catch (err) { setError(message(err, "Could not remove it.")); }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={`Higher roles: ${person.name}`}
      description={person.role === "none" ? "They see only what is listed here." : `Everywhere else they are ${roleLabel(person.role)}. A role here only adds access; a business unit's covers its projects.`}>
      {person.roles.length > 0 && (
        <ul className="idn-overrides">
          {person.roles.map((o) => (
            <li key={o.id}>
              {roleLabel(o.role)} on {o.target_type === "portfolio" ? "unit" : "project"} <strong>{names[o.target_id] ?? "(gone)"}</strong>{" "}
              <button type="button" className="idn-link" onClick={() => remove(o.id, names[o.target_id] ?? "it")} aria-label={`Remove ${roleLabel(o.role)} on ${names[o.target_id] ?? "it"}`}>Remove</button>
            </li>
          ))}
        </ul>
      )}
      <form onSubmit={add} className="idn-form">
        <fieldset className="idn-kind">
          <legend>On</legend>
          {(["project", "portfolio"] as const).map((k) => (
            <label key={k} className="idn-check"><input type="radio" name={`${id}-k`} checked={kind === k} onChange={() => { setKind(k); setTarget(""); }} />{k === "project" ? "A project" : "A business unit"}</label>
          ))}
        </fieldset>
        <label htmlFor={`${id}-t`}>{kind === "project" ? "Project" : "Business unit"}</label>
        <select id={`${id}-t`} value={target} onChange={(e) => setTarget(e.target.value)} required>
          <option value="">Choose…</option>
          {targets.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
        <label htmlFor={`${id}-ro`}>Role there</label>
        <select id={`${id}-ro`} value={role} onChange={(e) => setRole(e.target.value as OverrideRole)}>
          {OVERRIDE_ROLES.map(([r, l]) => <option key={r} value={r}>{l}</option>)}
        </select>
        {error && <p role="alert" className="idn-error">{error}</p>}
        <div className="idn-actions">
          <Button type="submit" variant="primary" disabled={!target}>Give this role</Button>
          <Button type="button" onClick={onClose}>Done</Button>
        </div>
      </form>
    </Dialog>
  );
}
