// Turning whatever someone types into the home page's "scan a GitHub repository" box into the one
// URL shape the API accepts (core/gitfetch.py: https, github.com, an owner/repo path).

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/; // GitHub's own rule for user and organization names
const REPO = /^[A-Za-z0-9._-]{1,100}$/;

export type RepoInput = { url: string; slug: string } | { error: string } | null;

/**
 * `owner/repo`, `github.com/owner/repo` or any https link inside a repository (a branch, a file, a
 * `.git` clone URL) becomes `https://github.com/owner/repo`. Empty input is `null` (nothing to say
 * yet); anything else that cannot be a public GitHub repository says why.
 */
export function githubRepo(raw: string): RepoInput {
  let s = raw.trim();
  if (!s) return null;
  s = s.replace(/^https?:\/\//i, "").replace(/^www\./i, "");
  const host = /^([a-z0-9.-]+\.[a-z]{2,})(\/|$)/i.exec(s)?.[1]?.toLowerCase();
  if (host && host !== "github.com") return { error: "Only GitHub repositories can be scanned from here." };
  if (host) s = s.slice(host.length);
  if (/[?#@\s\\]/.test(s)) return { error: "Use just the owner and repository, like owner/repo." };
  const [owner = "", repo = ""] = s.split("/").filter(Boolean);
  const name = repo.replace(/\.git$/i, "");
  if (!OWNER.test(owner)) return { error: "That is not a GitHub user or organization name." };
  if (!name) return { error: `Add the repository: ${owner}/repository-name.` };
  if (!REPO.test(name) || /^\.+$/.test(name)) return { error: "That is not a GitHub repository name." };
  return { url: `https://github.com/${owner}/${name}`, slug: `${owner}/${name}` };
}
