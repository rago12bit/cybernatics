"use client";

/* Read-only, syntax-highlighted code (plan §31: "Shiki for read-only highlighting"). The source
 * text is untrusted (it's the scanned repository's own code, per lib/types.ts's own warning at the
 * top of the file) — Shiki is a real tokenizer/highlighter, not a template engine: it HTML-escapes
 * every character of the input and only ever emits its own `<span style=...>` wrappers around that
 * escaped text, so rendering its output via dangerouslySetInnerHTML is the same safety property any
 * syntax highlighter relies on (the same reasoning applies to every other highlighter in this
 * codebase, e.g. the diff view). It never executes anything the source contains.
 *
 * The app has one theme, the site's dark blueprint (see tokens.css), so the code is always
 * highlighted with Shiki's dark theme, whatever the operating system's light/dark setting. */
import { useEffect, useState } from "react";
import { codeToHtml } from "shiki";

const EXT_LANG: Record<string, string> = {
  py: "python", js: "javascript", jsx: "jsx", ts: "typescript", tsx: "tsx",
  go: "go", rb: "ruby", java: "java", rs: "rust", php: "php", c: "c", cpp: "cpp",
  cs: "csharp", sh: "bash", yml: "yaml", yaml: "yaml", json: "json", tf: "hcl",
  dockerfile: "dockerfile", sql: "sql", html: "html", css: "css",
};

function languageFor(path: string): string {
  const base = path.split("/").pop() ?? path;
  if (base.toLowerCase() === "dockerfile") return "dockerfile";
  const ext = base.includes(".") ? base.split(".").pop()!.toLowerCase() : "";
  return EXT_LANG[ext] ?? "text";
}

export function CodeView({ code, path, highlightLine }: { code: string; path: string; highlightLine?: number }) {
  const [html, setHtml] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    codeToHtml(code, {
      lang: languageFor(path),
      theme: "github-dark",
      transformers: highlightLine
        ? [
            {
              line(node, line) {
                if (line === highlightLine) {
                  this.addClassToHast(node, "ds-code-highlight");
                }
              },
            },
          ]
        : [],
    }).then(
      (h) => { if (!cancelled) setHtml(h); },
      () => { if (!cancelled) setHtml(null); }, // an unrecognized language: fall back to plain text below
    );
    return () => { cancelled = true; };
  }, [code, path, highlightLine]);

  if (html === null) {
    return (
      <pre className="ds-code-plain" aria-label={`Code from ${path}`}>
        <code>{code}</code>
      </pre>
    );
  }
  // eslint-disable-next-line react/no-danger -- see the file header: Shiki escapes the source itself
  return <div className="ds-code-shiki" aria-label={`Code from ${path}`} dangerouslySetInnerHTML={{ __html: html }} />;
}
