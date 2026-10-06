"use client";

import { useEffect, useId, useState } from "react";
import { ApiError, getProjectOwner, listPeople, setProjectOwner } from "@/lib/api";
import type { Person, ProjectOwner as Owner } from "@/lib/types";
import "./advisories.css";

/** Who to ask about this project (plan §55.5): shown on advisory impact views, and assigned the
 * Issues created from an advisory. A person, chosen like an Issue's assignee. */
export function ProjectOwner({ assetId }: { assetId: string }) {
  const fid = useId();
  const [owner, setOwner] = useState<Owner | null>(null);
  const [people, setPeople] = useState<Person[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getProjectOwner(assetId).then(setOwner, () => setOwner(null));
    listPeople().then((p) => setPeople(Array.isArray(p) ? p : []), () => setPeople([]));
  }, [assetId]);

  if (!owner) return null;
  const current = people.find((p) => p.actor === owner.owner)?.handle ?? "";
  async function change(handle: string) {
    setBusy(true);
    setError(null);
    try {
      setOwner(await setProjectOwner(assetId, handle ? `@${handle}` : null));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not set the owner.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="ds-adv-owner">
      <label htmlFor={`${fid}-owner`} className="ds-ov-label">Owner</label>
      <select id={`${fid}-owner`} value={current} disabled={busy} onChange={(e) => change(e.target.value)}>
        <option value="">Nobody</option>
        {owner.owner && !current && <option value="" disabled>{owner.owner_name ?? owner.owner}</option>}
        {people.map((p) => <option key={p.actor} value={p.handle}>{p.name} (@{p.handle})</option>)}
      </select>
      {error && <p role="alert" className="ds-adv-error">{error}</p>}
    </div>
  );
}
