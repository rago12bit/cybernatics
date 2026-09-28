"use client";

/* Saved views (plan §28.3/§27's "Issues... filters, saved views"). No per-user identity/settings
 * backend exists yet (same honest limitation as design-system/mode.tsx), so these live in
 * localStorage per browser, keyed by project — a real, working feature, just not synced across
 * devices until there's a real user to attach it to. */
import { useCallback, useEffect, useState } from "react";
import type { IssuesQuery } from "./api";

export interface SavedView {
  name: string;
  query: IssuesQuery;
}

const keyFor = (assetId: string) => `bulwark.savedViews.${assetId}`;

function read(assetId: string): SavedView[] {
  try {
    const raw = localStorage.getItem(keyFor(assetId));
    return raw ? (JSON.parse(raw) as SavedView[]) : [];
  } catch {
    return [];
  }
}

function write(assetId: string, views: SavedView[]): void {
  try {
    localStorage.setItem(keyFor(assetId), JSON.stringify(views));
  } catch {
    /* storage unavailable: the view just won't survive a reload */
  }
}

export function useSavedViews(assetId: string): {
  views: SavedView[];
  save: (name: string, query: IssuesQuery) => void;
  remove: (name: string) => void;
} {
  const [views, setViews] = useState<SavedView[]>([]);
  useEffect(() => setViews(read(assetId)), [assetId]);

  const save = useCallback(
    (name: string, query: IssuesQuery) => {
      setViews((cur) => {
        const next = [...cur.filter((v) => v.name !== name), { name, query }];
        write(assetId, next);
        return next;
      });
    },
    [assetId],
  );

  const remove = useCallback(
    (name: string) => {
      setViews((cur) => {
        const next = cur.filter((v) => v.name !== name);
        write(assetId, next);
        return next;
      });
    },
    [assetId],
  );

  return { views, save, remove };
}
