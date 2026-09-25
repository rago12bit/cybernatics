# Reachability (v1)

For dependency (SCA) findings, Bulwark asks one question: **does the application's own code import this
package?** The answer is stored in `scoring.reachable` and explained in `scoring.risk_factors` ("Why this ranks
here" in the UI, `risk_factors` in JSON and SARIF).

| `reachable` | Meaning |
|---|---|
| `true` | An application source file imports the package (the reason names the file). |
| `false` | It is a declared dependency that no application file imports, or only test code does. |
| `null` | Cannot tell. Never treated as unreachable. |

## What it does

- Parses (never runs) `.py` with Python's `ast` and `.js .jsx .mjs .cjs .ts .tsx .mts .cts` with tree-sitter.
  Recognised: `import x`, `from x import y`, `importlib.import_module("x")`, `__import__("x")`; ES `import` and
  `export ... from`, CommonJS `require("x")`, dynamic `import("x")`. Imports in comments or strings do not count;
  `require(variable)` is not resolvable and does not count. Relative imports and Node built-ins are not packages.
- Reads the project's own manifests (`package.json`, `requirements*.txt`, `pyproject.toml`) to tell a **declared**
  dependency from a **transitive** one.
- Maps PyPI distribution names to import names (`PyYAML` is `yaml`, `Pillow` is `PIL`; a table plus common
  patterns). A hyphenated package whose import name cannot be determined stays unknown.
- Skips `node_modules`, virtualenvs, build output, `vendor` and hidden directories; does not follow symlinks;
  reads at most 20,000 files and 1 MB each.

## When the answer is "unknown" on purpose

Transitive dependency (nothing in your code imports it by design); package named in a string or in
`package.json` scripts (plugin, loader or CLI use); any source file that failed to parse; no source files at all;
ecosystems other than npm and PyPI (Maven, Go, Cargo and others are not analysed yet).

## Effect on the score

`reachable = false` multiplies the risk score by **0.85** (about the 0.15 weight the design plan gives
reachability) and lowers the CISA-KEV floor from 90 to 80. `true` and unknown change nothing. It is a nudge, not
a verdict, because of the limits below.

## Limits (read these)

- **Import is not call.** A package can be imported and the vulnerable function never called. v1 does not track
  symbols, so `true` means "used", not "exploitable".
- **`false` can be wrong through indirection.** The application may not import `mongodb` yet use it through
  `mongoose`; Flask loads Jinja2 without the app importing it. The reason text says "another dependency may
  still load it" for that reason. That is why the effect is small.
- **Frozen requirement files** list transitive packages as if declared, so they can be reported `false` when they
  are only used by another package.
- Dynamic imports built from variables, `exec`/`eval`, and code generated at build time are invisible.
- Monorepos are treated as one project: an import in one workspace counts for a same-named dependency in another.
- The analysis runs in the worker, outside the scanner sandbox: threat T14 in the threat model.

## Measured on the four sample repositories (dependency findings, latest scan of each)

Distinct vulnerable packages per repository and what the analysis said:

| Repository | Packages | `true` | `false` | unknown |
|---|---|---|---|---|
| NodeGoat | 83 | 6 | 1 | 76 (75 transitive, 1 named in scripts) |
| nodejs-goof | 100 | 15 | 2 | 83 (80 transitive, 3 named in code or scripts) |
| Vulnerable-Flask-App | 21 | 10 | 11 | 0 |
| VAmPI | 3 | 3 | 0 | 0 |

**Not an accuracy figure.** There is no ground truth. What was checked by hand: NodeGoat's one `false` (`async`)
is imported only from `test/`, as reported; nodejs-goof's `mongodb` and `npmconf` are indeed never imported by the
app, but `mongodb` is used through `mongoose`, which is exactly the indirection limit above. In Vulnerable-Flask-App
most of the 11 `false` results are packages from a fully pinned requirements file (Jinja2, click, certifi and
similar) that Flask and other packages use themselves: the "frozen requirements" limit in practice. The main
practical effect is that most dependency findings in real projects are transitive, and v1 cannot say anything
about those.
