"use client";

/* Read-only, syntax-highlighted code (plan §31: "Shiki for read-only highlighting"). The source
 * text is untrusted (it's the scanned repository's own code, per lib/types.ts's own warning at the
 * top of the file) — Shiki is a real tokenizer/highlighter, not a template engine: it HTML-escapes
 * every character of the input and only ever emits its own `<span style=...>` wrappers around that
 * escaped text, so rendering its output via dangerouslySetInnerHTML is the same safety property any
 * syntax highlighter relies on (the same reasoning applies to every other highlighter in this
 * codebase, e.g. the diff view). It never executes anything the source contains.
 *
 * One theme is picked at render time and re-fetched on change, rather than using Shiki's built-in
 * dual light/dark output (CSS custom properties keyed to a specific `.dark`/media-query convention)
 * -- this design system's dark mode is driven by `data-theme` on <html> (see tokens.css's header
 * comment on why), and reconciling the two conventions isn't worth the complexity for a read-only
 * code view. */
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

function isDarkNow(): boolean {
  if (typeof document === "undefined") return false;
  const attr = document.documentElement.getAttribute("data-theme");
  if (attr === "dark") return true;
  if (attr === "light") return false;
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: dark)").matches;
}

export function CodeView({ code, path, highlightLine }: { code: string; path: string; highlightLine?: number }) {
  const [html, setHtml] = useState<string | null>(null);
  const [dark, setDark] = useState(false);
  useEffect(() => setDark(isDarkNow()), []);
  useEffect(() => {
    const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
    const onChange = () => setDark(isDarkNow());
    mq?.addEventListener("change", onChange);
    const observer = new MutationObserver(onChange);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => {
      mq?.removeEventListener("change", onChange);
      observer.disconnect();
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    codeToHtml(code, {
      lang: languageFor(path),
      theme: dark ? "github-dark" : "github-light",
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
  }, [code, path, highlightLine, dark]);

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
