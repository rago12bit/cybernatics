/** A full page load to a path on this site (its own module so tests can watch where a page sends you). */
export function goTo(path: string): void {
  window.location.assign(path);
}
