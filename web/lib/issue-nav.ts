// j/k on the issue detail page (plan §28.3, §30.1, J3's "move through issues with j/k") needs to
// know the order the issues table showed, so pressing j/k there matches what was on screen -- not
// a second, independently-sorted fetch that could desync from it (the real bug the old scan report's
// FindingsTable.tsx hit once; see docs/v2-week33-verification.md). sessionStorage, same per-tab-only
// honesty as the API token itself: this is *the current page's* order, not a synced-across-devices
// "last viewed" list.
const KEY_PREFIX = "bulwark.issueNav.";

export function setIssueNavList(assetId: string, issueIds: string[]): void {
  try {
    sessionStorage.setItem(KEY_PREFIX + assetId, JSON.stringify(issueIds));
  } catch {
    /* storage unavailable: j/k on the detail page just won't move -- no crash */
  }
}

export function getIssueNavList(assetId: string): string[] {
  try {
    const raw = sessionStorage.getItem(KEY_PREFIX + assetId);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) && parsed.every((x) => typeof x === "string") ? parsed : [];
  } catch {
    return [];
  }
}
