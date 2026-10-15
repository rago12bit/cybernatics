// What ScrollReveal (components/site/ScrollReveal.tsx) brings into view. A plain module, so server
// components (the app layout) can pass these as strings.

/** What rises into view on the public pages: section headings, fact cells, table rows, steps, cards. */
export const REVEAL_SELECTOR = [
  ".site-sec > .sec-head",
  ".site-body > *",
  ".fact",
  ".cmp thead tr",
  ".cmp tbody tr",
  ".steps > li",
  ".cat-group > h2",
  ".cards > li",
  ".reveal-me",
].join(", ");

/** In the app: the blocks each screen is made of (panels, cards, sections), never rows inside a
 * table or list, which people scan and should not have to wait for. Titles rise in on load (CSS). */
export const APP_REVEAL_SELECTOR = [
  ".ds-shell-main > :not(.ds-page-head)",
  ".ds-shell-main > :not(.ds-page-head) > *",
  ".app-grid > *",
  ".reveal-me",
].join(", ");
