"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { ApiError, createGitScan, uploadScan } from "@/lib/api";
import { OPTIONAL_TOOLS, TOOLS } from "@/lib/types";

export function SubmitForm() {
  const router = useRouter();
  const [mode, setMode] = useState<"git" | "upload">("git");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [tools, setTools] = useState<string[]>([...TOOLS]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const ready = tools.length > 0 && (mode === "git" ? url.trim().startsWith("https://") : file !== null);
  // Say why Start is disabled instead of leaving a silently greyed-out button.
  const hints: string[] = [];
  if (mode === "git" && url.trim() !== "" && !url.trim().startsWith("https://")) hints.push("Use the full https:// address of a public repository.");
  if (tools.length === 0) hints.push("Choose at least one scanner.");

  // The file picker unmounts when you switch source type, so the chosen file must be forgotten with it.
  const switchMode = (m: "git" | "upload") => { setMode(m); setFile(null); setError(null); };

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const created = mode === "git" ? await createGitScan(url.trim(), tools) : await uploadScan(file as File, tools);
      router.push(`/scans/${created.id}`);
    } catch (err) {
      setError(err instanceof ApiError || err instanceof Error ? err.message : "Could not start the scan");
      setBusy(false);
    }
  }

  return (
    <form className="cell stack" onSubmit={submit} aria-labelledby="submit-h">
      <span className="eyebrow" id="submit-h">New scan</span>
      <div className="seg" role="group" aria-label="Source type">
        <button type="button" aria-pressed={mode === "git"} onClick={() => switchMode("git")}>Public Git URL</button>
        <button type="button" aria-pressed={mode === "upload"} onClick={() => switchMode("upload")}>Upload archive</button>
      </div>

      {mode === "git" ? (
        <>
          <label htmlFor="url">Repository URL</label>
          <input id="url" type="url" placeholder="https://github.com/owner/repo" value={url} onChange={(e) => { setUrl(e.target.value); setError(null); }} aria-describedby="url-help" />
          <p id="url-help" className="muted small">github.com, gitlab.com and bitbucket.org only. The default branch is scanned at depth 1.</p>
        </>
      ) : (
        <>
          <label htmlFor="file">Archive (.zip, .tar, .tar.gz)</label>
          <input id="file" type="file" accept=".zip,.tar,.tar.gz,.tgz" onChange={(e) => { setFile(e.target.files?.[0] ?? null); setError(null); }} />
          <p className="muted small">Uploaded archives are extracted in a size-limited, traversal-safe sandbox and deleted after the scan.</p>
        </>
      )}

      <fieldset>
        <legend>Scanners</legend>
        <div className="checks">
          {[...TOOLS, ...OPTIONAL_TOOLS].map((t) => (
            <label key={t} className="check">
              <input type="checkbox" checked={tools.includes(t)} onChange={(e) => setTools((cur) => (e.target.checked ? [...cur, t] : cur.filter((x) => x !== t)))} />
              {t}
            </label>
          ))}
        </div>
      </fieldset>

      {hints.length > 0 && <ul className="hint muted small" role="status">{hints.map((h) => <li key={h}>{h}</li>)}</ul>}
      {error && <p className="error" role="alert">{error}</p>}
      <button className="btn primary" disabled={!ready || busy}>{busy ? "Starting…" : "Start scan →"}</button>
    </form>
  );
}
