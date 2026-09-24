"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { ApiError, createGitScan, uploadScan } from "@/lib/api";
import { TOOLS } from "@/lib/types";

export function SubmitForm() {
  const router = useRouter();
  const [mode, setMode] = useState<"git" | "upload">("git");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [tools, setTools] = useState<string[]>([...TOOLS]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const ready = tools.length > 0 && (mode === "git" ? url.trim().startsWith("https://") : file !== null);

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
        <button type="button" aria-pressed={mode === "git"} onClick={() => setMode("git")}>Public Git URL</button>
        <button type="button" aria-pressed={mode === "upload"} onClick={() => setMode("upload")}>Upload archive</button>
      </div>

      {mode === "git" ? (
        <>
          <label htmlFor="url">Repository URL</label>
          <input id="url" type="url" placeholder="https://github.com/owner/repo" value={url} onChange={(e) => setUrl(e.target.value)} aria-describedby="url-help" />
          <p id="url-help" className="muted small">github.com, gitlab.com and bitbucket.org only. The default branch is scanned at depth 1.</p>
        </>
      ) : (
        <>
          <label htmlFor="file">Archive (.zip, .tar, .tar.gz)</label>
          <input id="file" type="file" accept=".zip,.tar,.tar.gz,.tgz" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          <p className="muted small">Uploaded archives are extracted in a size-limited, traversal-safe sandbox and deleted after the scan.</p>
        </>
      )}

      <fieldset>
        <legend>Scanners</legend>
        <div className="checks">
          {TOOLS.map((t) => (
            <label key={t} className="check">
              <input type="checkbox" checked={tools.includes(t)} onChange={(e) => setTools((cur) => (e.target.checked ? [...cur, t] : cur.filter((x) => x !== t)))} />
              {t}
            </label>
          ))}
        </div>
      </fieldset>

      {error && <p className="error" role="alert">{error}</p>}
      <button className="btn primary" disabled={!ready || busy}>{busy ? "Starting…" : "Start scan →"}</button>
    </form>
  );
}
