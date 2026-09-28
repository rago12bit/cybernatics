# Week 32 verification — design system (plan §29, §32)

Honest record of what was actually run, not just written, for the Week 32 deliverables: tokens as
CSS variables (light/dark), severity shapes and a contrast check in CI, Radix primitives restyled
to the tokens, Storybook with variants, self-hosted fonts.

## Scope decision, stated up front

Week 32's own line items (`web/design-system/`, `.storybook/`) are new and additive. **Nothing in
`web/app/**` or `web/components/**` was touched.** The live app still runs on its existing dark-only
"blueprint" theme (`web/app/globals.css`) — an already-built, deliberately different visual language
(all-caps mono labels, sharp 2px corners everywhere, no light mode) that predates this plan's §29
spec and doesn't currently follow it (§29.4 explicitly rules out all-caps labels, for one).

Reconciling those two is real, per-screen work, and the plan's own phasing agrees: Week 32 is
"Design system" (the foundation), and Weeks 33–35 ("App shell and overview," "Issues experience,"
"Onboarding, states, accessibility, validation") are where it actually gets applied, screen by
screen. Migrating the live app now would be a large, undiscussed rewrite outside this week's scope
and ahead of where the plan puts it. So: the tokens, shapes, primitives, and fonts below are real,
tested, and running in Storybook — not yet wired into anything a user can load at `/app` today.
That happens starting Week 33.

## What was actually verified, live, this session

- **`npm run typecheck`** — passes, 0 errors, across the whole `web/` package including the new
  `design-system/` and `.storybook/` directories.
- **`npm test`** — 137/137 tests pass, including the 18 new tests in
  `tests/design-tokens-contrast.test.ts`.
- **`npm run build`** (Next.js production build) — succeeds, confirming the new packages
  (`@radix-ui/*`, `@fontsource/*`) don't collide with anything the existing app imports.
- **`npm run build-storybook`** — succeeds, produces a working static Storybook with all 6 story
  files (Button, Dialog, DropdownMenu, Tabs, Tooltip, Severity).
- **A clean `npm ci` from the committed lockfile**, then the full sequence above run again — this
  is what CI actually runs (`.github/workflows/ci.yml`'s `web` job now has a
  `npm run build-storybook` step), not just what worked with a locally-mutated `node_modules`.
- **`npx storybook dev` was actually opened in a browser and driven by hand**, not just built:
  - The severity shapes (filled octagon/triangle/diamond/circle/ring) render as five visibly
    distinct shapes with distinct colors, in both themes.
  - The critical "not reachable" outline variant (§29.2's calm-by-default rule) was checked next to
    the filled/reachable version.
  - **The light/dark theme toggle was clicked and caught a real bug**: `tokens.css` keys its dark
    palette off `:root[data-theme="dark"]`, but the first version of the Storybook decorator set
    `data-theme` on a wrapper `<div>`, not `document.documentElement`. That div-level attribute
    never matches a `:root` selector, so the toggle silently did nothing and the sandbox browser's
    own `prefers-color-scheme: dark` decided the theme instead — which happened to look plausible
    enough in a single screenshot that it would have been easy to miss without actually clicking the
    control. Fixed in `.storybook/preview.tsx` with a `useEffect` that sets the attribute on
    `document.documentElement`; reloaded and re-clicked the toggle to confirm both themes now render
    their own token values (dark: `#161c24` surface with the lightened severity tints; light:
    `#f4f6f8` surface with the plan's own values).
  - The Dialog story's trigger button was clicked for real, confirming Radix's open/close state,
    the overlay, the 6px panel radius, and the floating-element shadow (elevation only on things
    that float, §29.4) all render as intended.

## Contrast check (plan §29.2's own requirement)

`tests/design-tokens-contrast.test.ts` reads the real token values out of
`design-system/tokens.css` (not a hand-copied literal) and checks every text token
(ink/muted/brand/all five severities) against both surface tokens (surface/raised), in both themes,
against the WCAG AA 4.5:1 threshold — 18 assertions, all passing. This mirrors the existing
`tests/contrast.test.ts` pattern already covering the old blueprint theme; the two are independent
and both run in CI, since the old theme isn't going away until Weeks 33–35 replace it screen by
screen.

The plan states its light-mode severity values were "chosen to meet at least 4.5:1 contrast on both
surface and raised." That claim was independently re-derived (not just trusted) with the same
relative-luminance math the contrast test uses, confirming all five hold on light — `medium` is the
tightest at 4.54:1 on `surface`, still clearing the bar. Dark-mode severity tints aren't specified
by the plan beyond "generated from them" — they were derived here by lightening each light value in
HSL space until it cleared 4.6:1 (a small margin over the 4.5:1 floor) against **both** dark
surfaces, then locked in and covered by the same CI test.

## Self-hosted fonts

`@fontsource/ibm-plex-sans` and `@fontsource/jetbrains-mono` (the real OFL-licensed font files,
vendored as npm packages rather than fetched from a Google Fonts `<link>`) are imported in
`design-system/fonts.css`. Ligatures are turned off on the mono face via
`font-feature-settings: "liga" 0, "calt" 0` — checked visually in Storybook that `!=` renders as two
distinct glyphs, not a single ligated one, per §29.3's explicit requirement.

## Radix primitives restyled to the tokens

`design-system/primitives/{Button,Tooltip,DropdownMenu,Dialog,Tabs}.tsx` wrap
`@radix-ui/react-{tooltip,dropdown-menu,dialog,tabs}` and style them entirely from
`design-system/primitives.css`, itself built only from the CSS custom properties in `tokens.css` —
no hard-coded colors. This is a deliberately small first set (the primitives Weeks 33's command
palette, project switcher, and dropdown menus will need first), not the full Radix catalog; more
get added as later weeks need them, restyled the same way.

## What Week 32 does not claim

- No live-app screen uses any of this yet (see "Scope decision" above) — that starts Week 33.
- Storybook isn't deployed anywhere; it's built and verified locally/in CI (`build-storybook`), not
  published to a URL. Publishing a hosted Storybook (e.g. Chromatic, GitHub Pages) wasn't asked for
  and would be a small, separate follow-up if wanted.
- The dark-mode severity tints are a reasonable derivation, not a designer's sign-off — if a real
  designer reviews this later and wants different values, the contrast test will catch any
  regression against AA, but it won't catch "technically passes AA but looks off" on its own.
