"use client";

import { useEffect, useState } from "react";
import { ApiError, listAttackPaths } from "@/lib/api";
import type { AttackPath, AttackPathNode } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./attack-paths-screen.css";

const KIND_LABEL: Record<AttackPathNode["kind"], string> = {
  entrypoint: "Entry point",
  issue: "Issue",
  secret: "Secret",
  cloud_resource: "Resource",
};

function edgeBetween(path: AttackPath, fromId: string, toId: string) {
  return path.edges.find((e) => e.source === fromId && e.target === toId);
}

function PathChain({ path }: { path: AttackPath }) {
  return (
    <ol className="ds-ap-chain">
      {path.nodes.map((node, i) => {
        const next = path.nodes[i + 1];
        const edge = next ? edgeBetween(path, node.id, next.id) : undefined;
        const isCheapest = node.id === path.cheapest_link;
        return (
          <li key={node.id} className="ds-ap-chain-item">
            <div className={`ds-ap-node ds-ap-node-${node.kind}${isCheapest ? " ds-ap-node-cheapest" : ""}`}>
              <span className="ds-ap-node-kind">{KIND_LABEL[node.kind]}</span>
              <span className="ds-ap-node-label">{node.label}</span>
              {node.detail && <span className="ds-ap-node-detail">{node.detail}</span>}
              {isCheapest && <span className="ds-ap-cheapest-badge">Fix this to break the chain</span>}
            </div>
            {next && (
              <span className="ds-ap-connector" aria-hidden="true">
                → {edge ? edge.kind.replace(/_/g, " ") : ""} →
              </span>
            )}
          </li>
        );
      })}
    </ol>
  );
}

export function AttackPathsScreen({ assetId }: { assetId: string }) {
  const [items, setItems] = useState<AttackPath[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [index, setIndex] = useState(0);

  useEffect(() => {
    listAttackPaths(assetId).then(
      (paths) => {
        setItems(paths);
        setIndex(0);
      },
      (e) => setError(e instanceof ApiError ? e.message : "Failed to load"),
    );
  }, [assetId]);

  return (
    <div className="ds-ap">
      <p className="small muted ds-ap-intro">
        Chains from an entry point through this project&apos;s own open issues to real impact,
        computed from the current scan -- never a hypothetical scenario. The narrative under each
        path, when shown, only describes the chain; it never adds a node or edge of its own.
      </p>

      {error && <p className="ds-ap-error" role="alert">{error}</p>}

      {items === null ? (
        <p className="small muted">Loading…</p>
      ) : items.length === 0 ? (
        <p className="ds-ap-empty">
          No attack paths found in this project&apos;s current open issues.
        </p>
      ) : (() => {
        const current = items[index];
        if (!current) return null;
        return (
        <div className="ds-ap-viewer">
          <div className="ds-ap-nav">
            <Button onClick={() => setIndex((i) => Math.max(0, i - 1))} disabled={index === 0}>
              ← Previous
            </Button>
            <span className="ds-ap-counter">
              Attack path {index + 1} of {items.length}
            </span>
            <Button
              onClick={() => setIndex((i) => Math.min(items.length - 1, i + 1))}
              disabled={index === items.length - 1}
            >
              Next →
            </Button>
          </div>

          <div className="ds-ap-badges">
            <span className={`ds-ap-badge ds-ap-likelihood-${current.likelihood}`}>
              Likelihood: {current.likelihood}
            </span>
            <span className={`ds-ap-badge ds-ap-impact-${current.impact}`}>
              Impact: {current.impact}
            </span>
          </div>

          <PathChain path={current} />

          {current.narrative ? (
            <p className="ds-ap-narrative">{current.narrative}</p>
          ) : (
            <p className="ds-ap-narrative ds-ap-narrative-missing">
              No narrative available (no model configured on this server for attack-path
              descriptions) -- the chain above is the real, computed data regardless.
            </p>
          )}
        </div>
        );
      })()}
    </div>
  );
}
