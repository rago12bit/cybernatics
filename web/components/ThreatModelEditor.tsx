"use client";

import { useEffect, useRef, useState } from "react";
import { ApiError, getThreatModel, regenerateThreatModel, saveThreatModel } from "@/lib/api";
import type { StrideRow, ThreatModel } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import { Loading } from "@/design-system/primitives/Loading";
import "./threat-model-editor.css";

/* The diagram is drawn inside its own frame (app/diagram-frame), not in this page. Mermaid puts a
 * <style> element and style="" attributes in its SVG, and inserts a copy into its document to measure
 * text; the app's CSP (proxy.ts) refuses both, so in production the diagram was unstyled and
 * unreadable. The frame has a policy that allows them; it draws whatever source this page posts it
 * and replies with the drawing's size. */
type FrameReply = { type: "bulwark-diagram"; request: number; ok: boolean; width?: number; height?: number };

function DiagramView({ mermaidText }: { mermaidText: string }) {
  const frame = useRef<HTMLIFrameElement>(null);
  const request = useRef(0);
  const [frameReady, setFrameReady] = useState(false);
  const [size, setSize] = useState<{ width: number; height: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    function onMessage(event: MessageEvent) {
      const data = event.data as FrameReply | undefined;
      if (event.origin !== window.location.origin || event.source !== frame.current?.contentWindow) return;
      if (data?.type !== "bulwark-diagram" || data.request !== request.current) return; // an older draw
      if (data.ok) {
        setError(null);
        setSize(data.width && data.height ? { width: data.width, height: data.height } : null);
      } else {
        setError("Could not render this diagram -- showing the raw source instead.");
      }
    }
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, []);

  useEffect(() => {
    const target = frame.current?.contentWindow;
    if (!frameReady || !target) return;
    request.current += 1;
    target.postMessage({ source: mermaidText, request: request.current }, window.location.origin);
  }, [mermaidText, frameReady]);

  return (
    <div className="ds-tm-diagram">
      {error && (
        <>
          <p className="ds-tm-error" role="alert">{error}</p>
          <pre className="ds-tm-raw">{mermaidText}</pre>
        </>
      )}
      <iframe
        ref={frame}
        src="/diagram-frame"
        title="Threat model diagram"
        className="ds-tm-frame"
        hidden={error !== null}
        // As wide as Mermaid drew it at most, at its aspect ratio (set through the CSSOM, which CSP allows).
        style={size ? { maxWidth: `${Math.ceil(size.width)}px`, aspectRatio: `${size.width} / ${size.height}` } : undefined}
        onLoad={() => setFrameReady(true)}
      />
    </div>
  );
}

function StrideTable({
  rows,
  editable,
  onChange,
}: {
  rows: StrideRow[];
  editable: boolean;
  onChange: (rows: StrideRow[]) => void;
}) {
  function update(i: number, field: "element" | "category" | "prompt", value: string) {
    const next = rows.slice();
    const row = next[i];
    if (!row) return;
    next[i] = { ...row, [field]: value } satisfies StrideRow;
    onChange(next);
  }
  function remove(i: number) {
    onChange(rows.filter((_, idx) => idx !== i));
  }
  return (
    <table className="ds-tm-table">
      <thead>
        <tr>
          <th>Element</th>
          <th>Kind</th>
          <th>STRIDE category</th>
          <th>Starter question</th>
          {editable && <th />}
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i}>
            <td>
              {editable ? (
                <input value={r.element} onChange={(e) => update(i, "element", e.target.value)} />
              ) : (
                r.element
              )}
            </td>
            <td>{r.element_kind.replace(/_/g, " ")}</td>
            <td>
              {editable ? (
                <input value={r.category} onChange={(e) => update(i, "category", e.target.value)} />
              ) : (
                r.category
              )}
            </td>
            <td>
              {editable ? (
                <textarea value={r.prompt} onChange={(e) => update(i, "prompt", e.target.value)} />
              ) : (
                r.prompt
              )}
            </td>
            {editable && (
              <td>
                <Button onClick={() => remove(i)}>Remove</Button>
              </td>
            )}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function ThreatModelEditor({ assetId }: { assetId: string }) {
  const [model, setModel] = useState<ThreatModel | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [draftMermaid, setDraftMermaid] = useState("");
  const [draftStride, setDraftStride] = useState<StrideRow[]>([]);
  const [saving, setSaving] = useState(false);
  const [regenerating, setRegenerating] = useState(false);

  useEffect(() => {
    getThreatModel(assetId).then(
      setModel,
      (e) => setError(e instanceof ApiError ? e.message : "Failed to load"),
    );
  }, [assetId]);

  function startEditing() {
    if (!model) return;
    setDraftMermaid(model.mermaid);
    setDraftStride(model.stride);
    setEditing(true);
  }

  async function save() {
    setSaving(true);
    setError(null);
    try {
      const saved = await saveThreatModel(assetId, draftMermaid, draftStride);
      setModel(saved);
      setEditing(false);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not save your edits");
    } finally {
      setSaving(false);
    }
  }

  async function regenerate() {
    setRegenerating(true);
    setError(null);
    try {
      const fresh = await regenerateThreatModel(assetId);
      setModel(fresh);
      setEditing(false);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not regenerate");
    } finally {
      setRegenerating(false);
    }
  }

  return (
    <div className="ds-tm">
      <p className="small muted ds-tm-intro">
        A starting point for your own review, generated from this project&apos;s code intelligence
        -- not an assessment. Edit the diagram or the table freely; regenerating discards your edits
        and rebuilds from the latest scan.
      </p>

      {error && <p className="ds-tm-error" role="alert">{error}</p>}

      {model === null ? (
        <Loading />
      ) : (
        <>
          <div className="ds-tm-meta">
            <span>Version {model.version}</span>
            <span className={`ds-tm-source ds-tm-source-${model.source}`}>{model.source}</span>
            {!editing && (
              <>
                <Button onClick={startEditing}>Edit</Button>
                <Button onClick={regenerate} disabled={regenerating}>
                  {regenerating ? "Regenerating…" : "Regenerate (discards edits)"}
                </Button>
              </>
            )}
          </div>

          {editing ? (
            <>
              <label className="ds-tm-label" htmlFor="tm-mermaid">
                Diagram source (Mermaid)
              </label>
              <textarea
                id="tm-mermaid"
                className="ds-tm-textarea"
                value={draftMermaid}
                onChange={(e) => setDraftMermaid(e.target.value)}
                rows={10}
              />
              <DiagramView mermaidText={draftMermaid} />
              <StrideTable rows={draftStride} editable onChange={setDraftStride} />
              <div className="ds-tm-actions">
                <Button onClick={() => setEditing(false)} disabled={saving}>
                  Cancel
                </Button>
                <Button variant="primary" onClick={save} disabled={saving}>
                  {saving ? "Saving…" : "Save"}
                </Button>
              </div>
            </>
          ) : (
            <>
              <DiagramView mermaidText={model.mermaid} />
              <StrideTable rows={model.stride} editable={false} onChange={() => {}} />
            </>
          )}
        </>
      )}
    </div>
  );
}
