"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import ReactGridLayout, { useContainerWidth, type Layout, type LayoutItem } from "react-grid-layout";
import "react-grid-layout/css/styles.css";
import "react-resizable/css/styles.css";
import {
  ApiError, copyDashboard, createDashboard, deleteDashboard, getDashboard, listAssets, listDashboards, listMetrics,
  listPortfolios, saveDashboard,
} from "@/lib/api";
import {
  CATALOGUE, COLS, ROLES, ROLE_LABEL, addWidget, describePlace, moveWidget, newWidgetId, readingOrder, resizeWidget,
  titleOf, toLayout, withLayout, type Dashboard, type DashboardList, type Role, type Widget, type WidgetFilters,
} from "@/lib/dashboard";
import type { AssetSummary, Portfolio } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import { Dialog } from "@/design-system/primitives/Dialog";
import { MetricWidget } from "./MetricWidget";
import { WidgetFiltersForm } from "./WidgetFiltersForm";
import "./dashboard.css";

/* Dashboards (plan §48.2, §55.4). Pick one; edit your own -- drag and resize with the mouse, or
 * focus a widget's Move button and use the arrow keys to move it and Shift + arrows to resize it,
 * each change announced -- then save. Share it with a role; anyone can copy what they can see. */

interface Draft {
  name: string;
  shared_with: Role[];
  widgets: Widget[];
  isNew: boolean;
}

const NARROW = 720;
const ARROWS: Record<string, [number, number]> = {
  ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1],
};

/** Which dashboard to open: the one asked for, else your own, else one shared with your role,
 * else the built-in program overview. */
export function pickDashboard(list: DashboardList, wanted?: string): Dashboard | undefined {
  const all = list.dashboards;
  return (
    all.find((d) => d.id === wanted) ??
    all.find((d) => !d.builtin && d.can_edit && d.owner !== null) ??
    all.find((d) => !d.builtin && list.role !== null && d.shared_with.includes(list.role)) ??
    all.find((d) => d.builtin) ??
    all[0]
  );
}

const sameWidgets = (a: Widget[], b: Widget[]) => JSON.stringify(a) === JSON.stringify(b);

/** The grid, measured from its own container (so the width hook mounts with it). Below 720 px the
 * widgets stack in reading order instead. */
function Grid({
  widgets, editing, frame, onSettled,
}: {
  widgets: Widget[];
  editing: boolean;
  frame: (w: Widget) => React.ReactNode;
  onSettled: (l: Layout, old: LayoutItem | null, item: LayoutItem | null) => void;
}) {
  const { width, containerRef, mounted } = useContainerWidth({ initialWidth: 1024 });
  const narrow = mounted && width < NARROW;
  return (
    <div ref={containerRef} className="dash-grid-host">
      {mounted && !narrow && (
        <ReactGridLayout
          layout={toLayout(widgets)}
          width={width}
          gridConfig={{ cols: COLS, rowHeight: 56, margin: [16, 16], containerPadding: [0, 0] }}
          dragConfig={{ enabled: editing, handle: ".dash-handle", threshold: 3 }}
          resizeConfig={{ enabled: editing, handles: ["se"] }}
          onDragStop={onSettled}
          onResizeStop={onSettled}
          className={editing ? "dash-grid editing" : "dash-grid"}
        >
          {widgets.map((w) => <div key={w.id} className="dash-cell">{frame(w)}</div>)}
        </ReactGridLayout>
      )}
      {narrow && <div className="dash-stack">{readingOrder(widgets).map((w) => <div key={w.id} className="dash-cell">{frame(w)}</div>)}</div>}
    </div>
  );
}

function useNarrow(): boolean {
  const [narrow, setNarrow] = useState(false);
  useEffect(() => {
    const q = window.matchMedia(`(max-width: ${NARROW - 1}px)`);
    setNarrow(q.matches);
    const on = () => setNarrow(q.matches);
    q.addEventListener("change", on);
    return () => q.removeEventListener("change", on);
  }, []);
  return narrow;
}

export function DashboardScreen({ initialId, embedded = false }: { initialId?: string; embedded?: boolean }) {
  const id = useId();
  const router = useRouter();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const narrow = useNarrow();
  const [list, setList] = useState<DashboardList | null>(null);
  const [current, setCurrent] = useState<Dashboard | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [announce, setAnnounce] = useState({ text: "", n: 0 });
  const [error, setError] = useState<string | null>(null);
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [portfolios, setPortfolios] = useState<Portfolio[]>([]);
  const [projects, setProjects] = useState<AssetSummary[]>([]);
  const [definitions, setDefinitions] = useState<Record<string, string>>({});
  const [filtering, setFiltering] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const say = useCallback((text: string) => setAnnounce((a) => ({ text, n: a.n + 1 })), []);
  const fail = (e: unknown, fallback: string) => setError(e instanceof ApiError ? e.message : fallback);

  const open = useCallback(
    (d: Dashboard | undefined) => {
      setCurrent(d ?? null);
      setDraft(null);
      setConflict(false);
      // On its own page the URL names the dashboard; embedded in a home, it leaves the URL alone.
      if (d && !embedded) router.replace(`/app/dashboards?d=${encodeURIComponent(d.id)}`, { scroll: false });
    },
    [router, embedded],
  );

  const load = useCallback(
    async (wanted?: string) => {
      try {
        const l = await listDashboards();
        setList(l);
        open(pickDashboard(l, wanted));
      } catch (e) {
        fail(e, "Could not load dashboards.");
      }
    },
    [open],
  );

  useEffect(() => {
    void load(initialId);
    listPortfolios().then(setPortfolios, () => setPortfolios([]));
    listAssets().then(setProjects, () => setProjects([]));
    listMetrics().then((ms) => setDefinitions(Object.fromEntries(ms.map((m) => [m.id, m.definition]))), () => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once, on arrival
  }, []);

  const names = useMemo(
    () => ({ ...Object.fromEntries(portfolios.map((p) => [p.id, p.name])), ...Object.fromEntries(projects.map((p) => [p.id, p.label])) }),
    [portfolios, projects],
  );

  const editing = draft !== null;
  const widgets = draft?.widgets ?? current?.widgets ?? [];

  function setWidgets(next: Widget[]) {
    setDraft((d) => (d ? { ...d, widgets: next } : d));
  }

  function onKey(e: React.KeyboardEvent, w: Widget) {
    const step = ARROWS[e.key];
    if (!step || !draft) return;
    e.preventDefault();
    const [dx, dy] = step;
    const next = e.shiftKey ? resizeWidget(draft.widgets, w.id, dx, dy) : moveWidget(draft.widgets, w.id, dx, dy);
    setWidgets(next);
    say(describePlace(next.find((x) => x.id === w.id)!, w));
  }

  // A mouse drag or resize, once it ends. (Not onLayoutChange: the grid also calls that with its
  // previous layout when the layout it is given changes, which would undo keyboard moves.)
  const settled = (layout: Layout, _old: LayoutItem | null, item: LayoutItem | null) => {
    if (!draft) return;
    const next = withLayout(draft.widgets, layout);
    if (!sameWidgets(next, draft.widgets)) setWidgets(next);
    const w = item && next.find((x) => x.id === item.i);
    if (w) say(describePlace(w));
  };

  function startEdit() {
    if (!current) return;
    setNotice(null);
    setFieldError(null);
    setDraft({ name: current.name, shared_with: [...current.shared_with], widgets: current.widgets.map((w) => ({ ...w })), isNew: false });
  }
  function startNew() {
    setNotice(null);
    setFieldError(null);
    setDraft({ name: "New dashboard", shared_with: [], widgets: [], isNew: true });
  }
  function cancel() {
    setDraft(null);
    setFieldError(null);
    setConflict(false);
    say("Edits discarded.");
  }

  async function save() {
    if (!draft) return;
    setBusy(true);
    setError(null);
    setFieldError(null);
    try {
      const body = { name: draft.name, shared_with: draft.shared_with, widgets: draft.widgets };
      const saved = draft.isNew ? await createDashboard(body) : await saveDashboard(current!.id, { ...body, version: current!.version });
      setList(await listDashboards());
      open(saved);
      setNotice(`Saved “${saved.name}”.`);
      say(`Saved ${saved.name}.`);
      headingRef.current?.focus();
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) setConflict(true);
      const d = e instanceof ApiError ? (e.data as { field?: string; message?: string } | undefined) : undefined;
      if (d?.message) setFieldError(d.message);
      else fail(e, "Could not save the dashboard.");
    } finally {
      setBusy(false);
    }
  }

  async function reloadCurrent() {
    if (!current) return;
    try {
      open(await getDashboard(current.id));
      setNotice("Reloaded the saved version; your unsaved edits were discarded.");
    } catch (e) {
      fail(e, "Could not reload the dashboard.");
    }
  }

  async function copy() {
    if (!current) return;
    setBusy(true);
    try {
      const c = await copyDashboard(current.id);
      setList(await listDashboards());
      open(c);
      setNotice(`Copied to “${c.name}”. This one is yours to change.`);
      headingRef.current?.focus();
    } catch (e) {
      fail(e, "Could not copy the dashboard.");
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!current) return;
    try {
      await deleteDashboard(current.id);
      setDeleting(false);
      setNotice(`Deleted “${current.name}”.`);
      await load();
      headingRef.current?.focus();
    } catch (e) {
      fail(e, "Could not delete the dashboard.");
    }
  }

  function add(metric: string) {
    if (!draft) return;
    const next = addWidget(draft.widgets, metric, newWidgetId(draft.widgets, metric));
    setWidgets(next);
    setAdding(false);
    const w = next[next.length - 1]!;
    say(`Added ${titleOf(w)} at row ${w.y + 1}.`);
  }
  function removeWidget(w: Widget) {
    if (!draft) return;
    setWidgets(draft.widgets.filter((x) => x.id !== w.id));
    say(`Removed ${titleOf(w)}.`);
    headingRef.current?.focus();
  }
  function applyFilters(w: Widget, f: WidgetFilters) {
    if (!draft) return;
    setWidgets(draft.widgets.map((x) => (x.id === w.id ? { ...x, filters: f } : x)));
    setFiltering(null);
    say(`Filters set on ${titleOf(w)}.`);
  }

  if (error && !list) return <p role="alert" className="dash-error">{error}</p>;
  if (!list || !current) return <p role="status">Loading dashboards…</p>;

  const mine = list.dashboards.filter((d) => !d.builtin && d.can_edit);
  const shared = list.dashboards.filter((d) => !d.builtin && !d.can_edit);
  const builtins = list.dashboards.filter((d) => d.builtin);
  const sharing = current.shared_with.map((r) => ROLE_LABEL[r]).join(", ");
  const filteringWidget = widgets.find((w) => w.id === filtering);

  const frame = (w: Widget) => (
    <div className="dash-frame">
      {editing && (
        <button type="button" className="dash-handle" aria-label={`Move ${titleOf(w)}`} aria-describedby={`${id}-keys`}
          onKeyDown={(e) => onKey(e, w)}>
          <span aria-hidden="true">⠿</span> Move
        </button>
      )}
      <MetricWidget
        widget={w}
        names={names}
        actions={editing && (
          <>
            <Button type="button" onClick={() => setFiltering(w.id)} aria-label={`Filters: ${titleOf(w)}`}>Filters</Button>
            <Button type="button" onClick={() => removeWidget(w)} aria-label={`Remove ${titleOf(w)}`}>Remove</Button>
          </>
        )}
      />
    </div>
  );

  return (
    <div className="dash">
      <div className="dash-top">
        <div>
          <span className="eyebrow">Dashboard</span>
          <h1 className="dash-name" ref={headingRef} tabIndex={-1}>{draft?.name || current.name}</h1>
          <p className="dash-muted dash-meta">
            {current.builtin ? "Built in" : current.can_edit ? "Yours" : `By ${current.owner}`}
            {sharing ? ` · shared with ${sharing}` : current.builtin ? "" : " · not shared"}
          </p>
        </div>
        {!editing && (
          <div className="dash-row">
            <label htmlFor={`${id}-pick`} className="dash-label">Open</label>
            <select id={`${id}-pick`} value={current.id} onChange={(e) => open(list.dashboards.find((d) => d.id === e.target.value))}>
              {mine.length > 0 && (
                <optgroup label="Yours">{mine.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}</optgroup>
              )}
              {shared.length > 0 && (
                <optgroup label="Shared with you">{shared.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}</optgroup>
              )}
              <optgroup label="Built in">{builtins.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}</optgroup>
            </select>
            {current.can_edit && <Button type="button" variant="primary" onClick={startEdit}>Edit</Button>}
            <Button type="button" onClick={copy} disabled={busy}>{current.can_edit ? "Duplicate" : "Copy to my dashboards"}</Button>
            <Button type="button" onClick={startNew}>New dashboard</Button>
            {current.can_edit && <Button type="button" onClick={() => setDeleting(true)}>Delete</Button>}
          </div>
        )}
      </div>

      {notice && <p role="status" className="dash-notice">{notice}</p>}
      {error && list && <p role="alert" className="dash-error">{error}</p>}

      {editing && draft && (
        <form className="dash-editbar" onSubmit={(e) => { e.preventDefault(); void save(); }} aria-label="Edit dashboard">
          <div className="dash-edit-fields">
            <div>
              <label htmlFor={`${id}-name`} className="dash-label">Name</label>
              <input id={`${id}-name`} value={draft.name} maxLength={80} required
                onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
            </div>
            <fieldset className="dash-share">
              <legend className="dash-label">Share with</legend>
              {ROLES.map((r) => (
                <label key={r}>
                  <input type="checkbox" checked={draft.shared_with.includes(r)}
                    onChange={() => setDraft({ ...draft, shared_with: draft.shared_with.includes(r)
                      ? draft.shared_with.filter((x) => x !== r) : [...draft.shared_with, r] })} /> {ROLE_LABEL[r]}
                </label>
              ))}
            </fieldset>
          </div>
          <p id={`${id}-keys`} className="dash-muted dash-small">
            Drag a widget by its Move button, or focus Move and press the arrow keys to move it and Shift with the arrow keys to resize it.
            {narrow && " On a narrow screen widgets are shown one above another, in the order they will have on a wide screen."}
          </p>
          {fieldError && (
            <div role="alert" className="dash-error">
              {fieldError}
              {conflict && <> <Button type="button" onClick={reloadCurrent}>Reload the saved version</Button></>}
            </div>
          )}
          <div className="dash-row">
            <Button type="button" onClick={() => setAdding(true)}>Add widget</Button>
            <Button type="submit" variant="primary" disabled={busy}>Save</Button>
            <Button type="button" onClick={cancel}>Cancel</Button>
          </div>
        </form>
      )}

      <div aria-live="polite" className="sr-only">{announce.text && <p key={announce.n}>{announce.text}</p>}</div>

      {widgets.length === 0 ? (
        <p className="dash-empty">{editing ? "No widgets yet. Choose Add widget to start." : "This dashboard has no widgets."}</p>
      ) : (
        <Grid widgets={widgets} editing={editing} frame={frame} onSettled={settled} />
      )}

      <Dialog open={adding} onOpenChange={setAdding} title="Add a widget" description="Each widget shows one metric; you can filter it after adding.">
        <ul className="dash-catalogue">
          {CATALOGUE.map((e) => (
            <li key={e.metric}>
              <Button type="button" onClick={() => add(e.metric)} aria-describedby={`${id}-def-${e.metric}`}>Add {e.title}</Button>
              <p id={`${id}-def-${e.metric}`} className="dash-muted dash-small">{definitions[e.metric] ?? ""}</p>
            </li>
          ))}
        </ul>
      </Dialog>

      <Dialog open={filteringWidget !== undefined} onOpenChange={(o) => !o && setFiltering(null)}
        title={filteringWidget ? `Filters: ${titleOf(filteringWidget)}` : "Filters"}>
        {filteringWidget && (
          <WidgetFiltersForm widget={filteringWidget} portfolios={portfolios} projects={projects}
            onApply={(f) => applyFilters(filteringWidget, f)} onCancel={() => setFiltering(null)} />
        )}
      </Dialog>

      <Dialog open={deleting} onOpenChange={setDeleting} title={`Delete “${current.name}”?`}
        description={current.shared_with.length ? "People it is shared with will no longer see it." : "This can't be undone."}>
        <div className="dash-row">
          <Button type="button" variant="primary" onClick={remove}>Delete</Button>
          <Button type="button" onClick={() => setDeleting(false)}>Keep it</Button>
        </div>
      </Dialog>
    </div>
  );
}
