# Heuristic evaluation of the current UI (Week 31, plan §32)

Evaluated 2026-09-28 against Nielsen's ten usability heuristics, by walking the actual running app
(`localhost:3010`, the sample scan and the real findings table/detail panel) rather than reading
the design intent alone. This is an **expert evaluation**, not a substitute for the baseline
usability study with five real participants (plan §32) — that study is still pending; see
docs/ux-study-protocol.md for the ready-to-run script. Where a heuristic issue is really a gap
against a plan-defined target journey rather than a heuristics violation per se, it's cross-referenced
to docs/ux-journey-maps.md instead of duplicated here.

## 1. Visibility of system status

- **Good:** scan progress shows each tool (bandit/semgrep/gitleaks/trivy/osv-scanner) with a live
  status chip (OK/skipped), a duration, and a findings count as it completes — this is real,
  specific status, not a generic spinner.
- **Issue found (real, observed):** the "Top 10 by risk" widget's own list does not highlight which
  row is currently open in the detail panel when you navigate with `j`/`k` — only the main findings
  table's list does. Confirmed directly: pressing `j` inside the Top 10 widget correctly advanced
  the panel to finding 2 of 10, but the left-hand list kept finding 1 highlighted. A user
  keyboard-triaging from the Top 10 widget loses track of which item is selected.

## 2. Match between system and the real world

- **Good:** severity labels (CRITICAL/HIGH/MEDIUM/LOW/INFO), plain risk descriptions ("An ingress
  security group rule allows traffic from 0.0.0.0/0"), and the "Fix these first" framing all use
  the user's own vocabulary, matching Principle 7 (§25) directly — no "Adapters," no "Suppress."
- **Issue found (real, observed, not hypothetical):** the static "How to fix" reference guidance
  shown for the AWS ingress-rule finding above is generic content about **service meshes, mTLS and
  Istio** — completely unrelated to fixing a security group rule. This is a real content-quality
  bug in the remediation knowledge base (`core/rag`), not a UI bug, but it directly violates this
  heuristic: the guidance doesn't match the real-world fix a developer needs for *this* finding.
  Worth a follow-up ticket against the KB corpus, independent of the UX redesign.

## 3. User control and freedom

- **Good:** `Esc` closes the finding detail panel cleanly; filters (severity/category/scanner/path)
  are all independently clearable.
- **Gap against the target, not a heuristic violation today:** J3's "mark as not a risk with a
  reason, or accept risk with an expiry" has no UI at all yet — there is nothing to give freedom
  *over*, since risk acceptance itself doesn't exist as a feature (ADR-0012 defers it to Week 62).
  Not a redesign problem to solve now.

## 4. Consistency and standards

- The finding detail panel's layout (severity/risk box → location → rule ids → code → guidance) is
  identical whether opened from the Top 10 widget or the main table — good internal consistency.
- Severity color coding is consistent across the scan-list page, the Top 10 widget, and the full
  findings table.

## 5. Error prevention

- The sign-in screen's help text ("It stays in this browser tab only and is never put in a URL")
  proactively prevents a real mistake (pasting a token into a URL/query string) before it happens —
  a strong example of this heuristic done well.
- File-path filtering and severity/category filters are dropdowns/checkboxes, not free text prone
  to typos, except the path filter (a deliberate, reasonable exception — substring search needs it).

## 6. Recognition rather than recall

- Every finding's location, rule id, and CVSS/EPSS numbers are shown inline in the detail panel —
  a user never has to remember a rule id to look it up elsewhere.
- **Issue found:** there is no visible on-screen hint that `j`/`k` (or the up/down arrow buttons)
  navigate between findings until a user either discovers the arrow buttons or already knows the
  convention from another keyboard-first tool (email clients, Vim). Principle 5 (§25) commits to
  "keyboard-first triage," but nothing teaches a novice the keys exist. A brief, dismissible hint or
  a `?` shortcuts-help overlay (the plan's own §30.1 "command palette, keyboard map, shortcut help,"
  scheduled for Week 33) would close this.

## 7. Flexibility and efficiency of use

- Sorting by severity, path, or risk score, plus scanner/category filters, gives a security
  engineer (per §26.1's persona table) real flexibility for triage.
- `j`/`k` navigation on the full findings table works well for the "triage 100 issues" persona goal
  once discovered (see #6 above).

## 8. Aesthetic and minimalist design

- The severity bars, dedup summary ("62 raw findings became 38 after merging duplicates, 39%
  fewer") and the plain-language top line are calm and information-dense without clutter — matches
  Principle 2, "calm by default," directly.

## 9. Help users recognize, diagnose, and recover from errors

- Not exercised in this pass without real error states (a failed scan, a timed-out tool) — the
  sample scan is a clean "completed" run. Deferred to the actual usability study, which should
  include a task that hits a partial/failed scan if one can be arranged.

## 10. Help and documentation

- The "About Bulwark" page and inline explanatory copy ("Ranked by severity and how likely each one
  is to be exploited... a heuristic for ordering work, not a guarantee") reduce the need for
  separate docs for the core flows.
- No in-app shortcuts/keyboard-map documentation yet (ties back to #6) — scheduled work, not a new
  finding.

## Summary: prioritized list of UX problems (plan §31's own deliverable)

1. **Top 10 widget's list doesn't track keyboard navigation** (visibility of system status) — small,
   concrete fix.
2. **No shortcut discoverability** for `j`/`k` (recognition vs. recall) — addressed by the plan's
   own Week 33 command-palette/shortcut-help work; flagged here so it isn't lost.
3. **KB remediation guidance can be topically wrong** (match between system and real world) — a
   content-quality bug, not a UX-redesign item; worth its own ticket against `core/rag`.
4. **J1's "sign in with GitHub" doesn't match reality** (still API-token paste) and **J3's risk-
   acceptance actions don't exist yet** — both are journey-target gaps, detailed in
   docs/ux-journey-maps.md, not heuristic violations of the current design.
