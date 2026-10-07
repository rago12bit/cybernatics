"use client";

import { useEffect, useId, useState } from "react";
import { ApiError, copyIssueView, createIssueView, deleteIssueView, getAssetOverview, importIssueViews, saveIssueView } from "@/lib/api";
import type { Role } from "@/lib/dashboard";
import { LEGACY_DONE, legacyToQuery, readLegacyViews, type Column, type SavedView, type Sort } from "@/lib/issues";
import { Button } from "@/design-system/primitives/Button";
import { Dialog } from "@/design-system/primitives/Dialog";

/* Saved views (plan §56): yours, those shared with your role, and the built-in ones. A view is a
 * query, a sort and columns; open one and the panel, the query bar and the address all follow.
 * Views saved in this browser before are offered for import once. */

const ROLES: [Role, string][] = [["lead", "Leads"], ["engineer", "Engineers"], ["tester", "Testers"]];

function message(e: unknown, fallback: string): string {
  if (e instanceof ApiError) return (e.data as { message?: string } | undefined)?.message ?? e.message;
  return fallback;
}

function storage(): Storage | null {
  try { return window.localStorage; } catch { return null; }
}

export function ViewsPanel({ views, active, current, onOpen, onChanged, me }: {
  views: SavedView[];
  active: SavedView | null;
  current: { query: string; sort: Sort; columns: Column[] };
  onOpen: (v: SavedView | null) => void;
  onChanged: (list: SavedView[] | null, open?: SavedView | null) => void;
  me: string | null;
}) {
  const id = useId();
  const [saving, setSaving] = useState<"new" | null>(null);
  const [name, setName] = useState("");
  const [share, setShare] = useState<Role[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [legacy, setLegacy] = useState(0);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState<string | null>(null);

  useEffect(() => {
    const st = storage();
    if (!st || st.getItem(LEGACY_DONE)) return;
    setLegacy(readLegacyViews(st).length);
  }, []);

  const mine = views.filter((v) => !v.builtin && v.owner === me);
  const shared = views.filter((v) => !v.builtin && v.owner !== me);
  const builtin = views.filter((v) => v.builtin);
  const edited = active !== null && (active.query !== current.query || active.sort !== current.sort);

  async function saveNew() {
    setBusy(true); setError(null);
    try {
      const v = await createIssueView({ name: name.trim(), query: current.query, sort: current.sort, columns: current.columns, shared_with: share });
      setSaving(null); setName(""); setShare([]);
      setNotice(`Saved “${v.name}”.`);
      onChanged(null, v);
    } catch (e) { setError(message(e, "Could not save the view.")); }
    finally { setBusy(false); }
  }

  async function saveChanges() {
    if (!active) return;
    setBusy(true); setError(null);
    try {
      const v = await saveIssueView(active.id, { version: active.version, query: current.query, sort: current.sort, columns: current.columns });
      setNotice(`Saved changes to “${v.name}”.`);
      onChanged(null, v);
    } catch (e) { setError(message(e, "Could not save the view.")); }
    finally { setBusy(false); }
  }

  async function remove() {
    if (!active) return;
    setBusy(true); setError(null);
    try {
      await deleteIssueView(active.id);
      setNotice(`Deleted “${active.name}”.`);
      setConfirming(null);
      onChanged(null, null);
    } catch (e) { setError(message(e, "Could not delete the view.")); }
    finally { setBusy(false); }
  }

  async function copy() {
    if (!active) return;
    setBusy(true); setError(null);
    try {
      const v = await copyIssueView(active.id);
      setNotice(`Copied to your views as “${v.name}”.`);
      onChanged(null, v);
    } catch (e) { setError(message(e, "Could not copy the view.")); }
    finally { setBusy(false); }
  }

  async function importLegacy() {
    const st = storage();
    if (!st) return;
    setBusy(true); setError(null);
    try {
      const old = readLegacyViews(st);
      const labels = new Map<string, string | null>();
      for (const assetId of new Set(old.map((v) => v.assetId))) {
        labels.set(assetId, await getAssetOverview(assetId).then((o) => o.asset.label, () => null));
      }
      const ready = old.flatMap((v) => {
        const label = labels.get(v.assetId);
        try { return label ? [legacyToQuery(v, label)] : []; } catch { return []; }
      });
      const lost = old.length - ready.length;
      const r = ready.length ? await importIssueViews(ready) : { imported: [], skipped: 0 };
      st.setItem(LEGACY_DONE, new Date().toISOString());
      setLegacy(0);
      setNotice(`Imported ${r.imported.length} view${r.imported.length === 1 ? "" : "s"}`
        + (r.skipped ? `; ${r.skipped} you already had` : "")
        + (lost ? `; ${lost} for projects that no longer exist were left out` : "") + ".");
      onChanged(null);
    } catch (e) { setError(message(e, "Could not import the views.")); }
    finally { setBusy(false); }
  }

  const list = (title: string, items: SavedView[]) => items.length > 0 && (
    <>
      <h3 className="iss-label">{title}</h3>
      <ul className="iss-viewlist">
        {items.map((v) => (
          <li key={v.id}>
            <button type="button" aria-current={active?.id === v.id ? "true" : undefined} onClick={() => onOpen(active?.id === v.id ? null : v)} title={v.query || "the active queue"}>
              {v.name}{v.shared_with.length > 0 && !v.builtin && <span className="iss-muted"> · shared</span>}
            </button>
          </li>
        ))}
      </ul>
    </>
  );

  return (
    <section className="iss-views" aria-labelledby={`${id}-h`}>
      <h2 id={`${id}-h`} className="iss-views-head">Saved views</h2>
      {legacy > 0 && (
        <div className="iss-import">
          <p>{legacy} view{legacy === 1 ? " is" : "s are"} saved in this browser from the project tables. Import {legacy === 1 ? "it" : "them"} so {legacy === 1 ? "it follows" : "they follow"} you to any device?</p>
          <Button type="button" onClick={importLegacy} disabled={busy}>Import</Button>
        </div>
      )}
      {list("Yours", mine)}
      {list("Shared with you", shared)}
      {list("Built in", builtin)}
      <div className="iss-view-actions">
        {active && active.can_edit && edited && <Button type="button" onClick={saveChanges} disabled={busy}>Save changes to “{active.name}”</Button>}
        <Button type="button" onClick={() => { setSaving("new"); setName(""); }} disabled={busy}>Save as a view…</Button>
        {active && !active.can_edit && <Button type="button" onClick={copy} disabled={busy}>Copy to my views</Button>}
        {active && active.can_edit && (confirming === active.id
          ? <Button type="button" onClick={remove} disabled={busy}>Delete “{active.name}” for good</Button>
          : <Button type="button" onClick={() => setConfirming(active.id)} disabled={busy} aria-label={`Delete the view ${active.name}`}>Delete view</Button>)}
      </div>
      {notice && <p role="status" className="iss-small">{notice}</p>}
      {error && <p role="alert" className="iss-error">{error}</p>}
      <Dialog open={saving === "new"} onOpenChange={(o) => !o && setSaving(null)} title="Save as a view"
        description="The filters, the sort and the columns, under a name. Only you can change it.">
        <div className="iss-field">
          <label htmlFor={`${id}-name`} className="iss-label">Name</label>
          <input id={`${id}-name`} value={name} maxLength={80} onChange={(e) => setName(e.target.value)} />
        </div>
        <fieldset className="iss-values">
          <legend className="iss-label">Share with</legend>
          {ROLES.map(([r, label]) => (
            <label key={r} className="iss-check">
              <input type="checkbox" checked={share.includes(r)} onChange={(e) => setShare((s) => (e.target.checked ? [...s, r] : s.filter((x) => x !== r)))} />
              {label}
            </label>
          ))}
          <p className="iss-small iss-muted">They can open it and copy it, not change it.</p>
        </fieldset>
        <p className="iss-small">Query: <code>{current.query || "(the active queue)"}</code></p>
        {error && <p role="alert" className="iss-error">{error}</p>}
        <div className="iss-actions">
          <Button type="button" variant="primary" onClick={saveNew} disabled={busy || !name.trim()}>Save</Button>
          <Button type="button" onClick={() => setSaving(null)}>Cancel</Button>
        </div>
      </Dialog>
    </section>
  );
}
