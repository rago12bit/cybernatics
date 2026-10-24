import Link from "next/link";
import { byKind, counts } from "@/lib/catalogue";

/* Where Bulwark sits: what comes in, what it decides, what goes out. Every name below comes from the
   integrations catalogue (lib/integrations.json, generated from the code's own registries), so the
   diagram cannot list something Bulwark does not do. HTML, not SVG: it reflows to a column on a phone. */

type Part = { title: string; detail: string };

const names = (items: { name: string }[]) => items.map((i) => i.name);
const sentence = (xs: string[]) => (xs.length < 2 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs.at(-1)}`);

/** Labels for catalogue entries, shown only for the ids the catalogue actually has. */
function pick(kind: Parameters<typeof byKind>[0], labels: [string, string][]): string[] {
  const have = new Set(byKind(kind).map((i) => i.id));
  return labels.filter(([id]) => have.has(id)).map(([, label]) => label);
}

export function whereItSits() {
  const c = counts();
  const formats = pick("import", [["import:sarif", "SARIF"], ["import:nessus", "Nessus"], ["import:burp", "Burp Suite"], ["import:zap", "ZAP"], ["import:snyk", "Snyk"]]);
  const pulls = pick("connector", [["connector:github_code_scanning", "GitHub code scanning"], ["connector:github_dependabot", "Dependabot"], ["connector:gitlab", "GitLab"], ["connector:defectdojo_import", "DefectDojo"]]);
  const pushes = pick("connector", [["connector:defectdojo_export", "DefectDojo"]]);
  const web = byKind("scanner").filter((s) => s.mode === "passive" || s.mode === "active");
  const notify = pick("notifications", [["notify:slack", "Slack"], ["notify:teams", "Microsoft Teams"], ["notify:discord", "Discord"], ["notify:email", "email"], ["notify:webhooks", "webhooks"]]);

  const inputs: Part[] = [
    { title: "Repositories", detail: "GitHub, GitLab and Bitbucket, a folder or an archive" },
    { title: "Pull requests", detail: "The GitHub Action scans each change; /fix proposes a patch" },
    { title: `Reports in ${c.parsers} formats`, detail: `${formats.join(", ")} and more, or any other through a mapping` },
    { title: "Connectors", detail: `${sentence(pulls)}, on a schedule` },
    { title: "Running sites", detail: `${sentence(web.map((s) => s.name))}, on a site you have verified` },
  ];
  const outputs: Part[] = [
    { title: "Tickets", detail: `${sentence(names(byKind("tickets")))}, kept in sync both ways` },
    { title: "Notifications", detail: sentence(notify) },
    { title: "Code scanning", detail: "SARIF uploads and pull request comments" },
    { title: "Evidence", detail: "Signed PDF reports, evidence packs, VEX and SBOMs" },
    { title: "Your agent", detail: "An MCP server, read-only by default" },
    ...(pushes.length ? [{ title: "DefectDojo", detail: "Findings pushed into an engagement" }] : []),
  ];
  const decides = [
    `${c.scanners} scanners, each in its own sandbox`,
    "One shape for every finding",
    "Merged across tools",
    "Ranked by risk",
    "Tracked as Issues, with SLAs",
  ];
  return { inputs, outputs, decides };
}

function Column({ id, label, parts }: { id: string; label: string; parts: Part[] }) {
  return (
    <div className={`wis-col wis-${id}`}>
      <span className="wis-label" id={`wis-${id}`}>{label}</span>
      <ul aria-labelledby={`wis-${id}`}>
        {parts.map((p) => (
          <li key={p.title}>
            <span className="wis-t">{p.title}</span>
            <span className="wis-d">{p.detail}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function WhereItSits() {
  const { inputs, outputs, decides } = whereItSits();
  return (
    <section className="section wis" id="where" aria-labelledby="where-h">
      <div className="sec-head">
        <div className="stack">
          <span className="eyebrow">Where it sits</span>
          <h2 id="where-h">It reads what your stack already produces, and decides in one place.</h2>
        </div>
        <div className="actions"><Link href="/integrations" className="btn sm">Every integration →</Link></div>
      </div>
      <div className="wis-map grid-bg">
        <div className="brackets" aria-hidden="true"><i /><i /><i /><i /></div>
        <Column id="in" label="Comes in" parts={inputs} />
        <div className="wis-core">
          <span className="wis-label" id="wis-core">Bulwark · on your servers</span>
          <ol aria-labelledby="wis-core">
            {decides.map((d, i) => <li key={d}><span className="wis-n">{String(i + 1).padStart(2, "0")}</span>{d}</li>)}
          </ol>
        </div>
        <Column id="out" label="Goes out" parts={outputs} />
      </div>
    </section>
  );
}
