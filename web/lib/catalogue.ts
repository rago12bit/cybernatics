import data from "./integrations.json";

// The integrations catalogue, generated from the code's own registries by
// scripts/gen-integrations.py (tests/unit/test_integrations.py keeps it current). Never edit the JSON.

export type Kind = "scanner" | "import" | "connector" | "tickets" | "notifications" | "agents";

export type Integration = {
  id: string;
  name: string;
  kind: Kind;
  how: string;
  categories?: string[];
  languages?: string[];
  version?: string;
  mode?: string; // scanner: default | opt-in | hosted | passive | active
  formats?: string[];
  dedup?: string;
  ported_from_defectdojo?: boolean;
  direction?: string; // connector: pull | push
  credential?: boolean;
  permissions?: string;
};

export const CATEGORY_LABELS = data.categories as Record<string, string>;
export const INTEGRATIONS = data.items as Integration[];

export const KIND_LABELS: Record<Kind, string> = {
  scanner: "Scanners",
  import: "Report imports",
  connector: "Connectors",
  tickets: "Tickets",
  notifications: "Notifications",
  agents: "Your agent and pull requests",
};
export const KINDS = Object.keys(KIND_LABELS) as Kind[];

export function byKind(kind: Kind, items: Integration[] = INTEGRATIONS): Integration[] {
  return items.filter((i) => i.kind === kind);
}

export function counts(items: Integration[] = INTEGRATIONS) {
  const scanners = byKind("scanner", items);
  return {
    scanners: scanners.length,
    defaultScanners: scanners.filter((s) => s.mode === "default").length,
    parsers: byKind("import", items).filter((i) => i.id !== "import:universal").length,
    connectors: byKind("connector", items).length,
  };
}

/** Filter by kind (or all), category and a free-text query over the name and the details. */
export function filterIntegrations(items: Integration[], kind: Kind | "all", category: string, query: string): Integration[] {
  const q = query.trim().toLowerCase();
  return items.filter(
    (i) =>
      (kind === "all" || i.kind === kind) &&
      (!category || (i.categories ?? []).includes(category)) &&
      (!q ||
        [
          i.name, i.how, i.id, KIND_LABELS[i.kind], i.permissions ?? "",
          ...(i.formats ?? []), ...(i.languages ?? []),
          // "dast", "sca", "secrets": what people type, as the key and as the label
          ...(i.categories ?? []).flatMap((c) => [c, CATEGORY_LABELS[c] ?? ""]),
        ]
          .join(" ")
          .toLowerCase()
          .includes(q)),
  );
}

export const MODE_LABELS: Record<string, string> = {
  default: "Runs by default",
  "opt-in": "Opt-in",
  hosted: "Hosted mode",
  passive: "Passive campaign",
  active: "Active campaign",
};

export const DEDUP_LABELS: Record<string, string> = {
  fingerprint_v2: "fingerprint",
  tool_id: "the tool's own id",
  package: "package and advisory",
  hash_fields: "chosen fields",
  tool_id_or_hash: "tool id, else fields",
};
