"use client";

/* Read-only, syntax-highlighted code (plan §31: "Shiki for read-only highlighting"). The source
 * text is untrusted (it's the scanned repository's own code, per lib/types.ts's own warning at the
 * top of the file), so it is never handed to the browser as HTML: Shiki only tokenizes it, and each
 * token is rendered as a React text node.
 *
 * Two things the production CSP (proxy.ts) forbids, and this used to rely on: Shiki's default regex
 * engine is WebAssembly (`wasm-eval`, not allowed by script-src), and `codeToHtml` returns
 * `<span style="color:...">` markup, whose style attributes style-src drops when it is inserted as
 * HTML. In production every snippet fell back to plain text. The JavaScript regex engine needs no
 * WebAssembly, and React sets a token's colour through the CSSOM, which CSP does not govern.
 *
 * The app has one theme, the site's dark blueprint (see tokens.css), so the code is always
 * highlighted with Shiki's dark theme, whatever the operating system's light/dark setting. */
import { useEffect, useState, type CSSProperties } from "react";
import {
  createHighlighter,
  createJavaScriptRegexEngine,
  type BundledLanguage,
  type Highlighter,
  type ThemedToken,
} from "shiki";

const THEME = "github-dark";

let highlighter: Promise<Highlighter> | null = null;

async function tokenize(code: string, lang: string): Promise<ThemedToken[][]> {
  highlighter ??= createHighlighter({
    themes: [THEME],
    langs: [],
    // Forgiving: a grammar rule the JavaScript engine can't express is skipped, not fatal.
    engine: createJavaScriptRegexEngine({ forgiving: true }),
  });
  const h = await highlighter;
  await h.loadLanguage(lang as BundledLanguage);
  return h.codeToTokens(code, { lang: lang as BundledLanguage, theme: THEME }).tokens;
}

// Shiki's FontStyle bit flags (from vscode-textmate); -1 is "not set".
function tokenStyle(t: ThemedToken): CSSProperties {
  const f = t.fontStyle ?? 0;
  return {
    color: t.color,
    fontStyle: f > 0 && f & 1 ? "italic" : undefined,
    fontWeight: f > 0 && f & 2 ? "bold" : undefined,
    textDecoration: f > 0 && f & 4 ? "underline" : undefined,
  };
}

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
  const [lines, setLines] = useState<ThemedToken[][] | null>(null);

  useEffect(() => {
    let cancelled = false;
    const lang = languageFor(path);
    setLines(null);
    if (lang === "text") return;
    tokenize(code, lang).then(
      (t) => { if (!cancelled) setLines(t); },
      () => { if (!cancelled) setLines(null); }, // a grammar that failed to load: plain text below
    );
    return () => { cancelled = true; };
  }, [code, path]);

  if (lines === null) {
    return (
      <pre className="ds-code-plain" aria-label={`Code from ${path}`}>
        <code>{code}</code>
      </pre>
    );
  }
  return (
    <div className="ds-code-shiki" aria-label={`Code from ${path}`}>
      <pre className={`shiki ${THEME}`} tabIndex={0}>
        <code>
          {lines.map((line, i) => (
            <span key={i}>
              {i > 0 && "\n"}
              <span className={i + 1 === highlightLine ? "line ds-code-highlight" : "line"}>
                {line.map((t, j) => <span key={j} style={tokenStyle(t)}>{t.content}</span>)}
              </span>
            </span>
          ))}
        </code>
      </pre>
    </div>
  );
}
