"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, getAssetVerification, registerWebAsset, verifyAsset } from "@/lib/api";
import type { AssetVerification } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./web-asset-verify.css";

/** Registering and verifying ownership of a web/DAST target (plan §22.4) -- the gate every DAST
 * campaign (Week 49 task 3) sits behind. `assetId` present: load and show an existing
 * registration's current state (used by `/app/projects/[id]/verify`). Absent: shows the
 * registration form first, then the same instructions/check-now view once submitted (used by
 * `/app/projects/new-web`) -- no navigation needed, the component just swaps its own view. */
export function WebAssetVerification({ assetId }: { assetId?: string }) {
  const [verification, setVerification] = useState<AssetVerification | null>(null);
  const [domain, setDomain] = useState("");
  const [method, setMethod] = useState<"dns_txt" | "well_known">("dns_txt");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!assetId) return;
    getAssetVerification(assetId).then(setVerification, (e) =>
      setError(e instanceof ApiError ? e.message : "Failed to load"),
    );
  }, [assetId]);

  async function register() {
    if (!domain.trim()) {
      setError("Enter a domain, e.g. example.com.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setVerification(await registerWebAsset(domain.trim(), method));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not register this target");
    } finally {
      setBusy(false);
    }
  }

  async function checkNow() {
    if (!verification) return;
    setBusy(true);
    setError(null);
    try {
      setVerification(await verifyAsset(verification.asset_id));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not run the check");
    } finally {
      setBusy(false);
    }
  }

  if (!verification) {
    return (
      <div>
        <p className="small muted ds-wav-intro">
          Prove you control a domain before Bulwark will run any DAST scan against it (plan
          §22.4) -- scanning a site without permission isn&apos;t a feature, it&apos;s an attack.
          Choose a domain and a verification method below.
        </p>
        {error && <p className="ds-wav-error" role="alert">{error}</p>}
        <div className="ds-wav-row">
          <label className="ds-wav-label" htmlFor="wav-domain" style={{ marginBottom: 0 }}>
            Domain
          </label>
          <input
            id="wav-domain"
            type="text"
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
          />
        </div>
        <fieldset className="ds-wav-methods">
          <legend className="ds-wav-label">Verification method</legend>
          <label>
            <input
              type="radio"
              name="wav-method"
              checked={method === "dns_txt"}
              onChange={() => setMethod("dns_txt")}
            />
            DNS TXT record
          </label>
          <label>
            <input
              type="radio"
              name="wav-method"
              checked={method === "well_known"}
              onChange={() => setMethod("well_known")}
            />
            .well-known file
          </label>
        </fieldset>
        <Button variant="primary" onClick={register} disabled={busy}>
          {busy ? "Registering…" : "Register target"}
        </Button>
      </div>
    );
  }

  return (
    <div>
      {error && <p className="ds-wav-error" role="alert">{error}</p>}
      <p>
        Target: <strong>{verification.domain}</strong>
      </p>
      <dl className="ds-wav-instructions">
        {verification.method === "dns_txt" ? (
          <>
            <dt>Create a DNS TXT record</dt>
            <dd>
              Name: <code className="ds-wav-code">{verification.record_name}</code>
            </dd>
            <dd>
              Value: <code className="ds-wav-code">{verification.record_value}</code>
            </dd>
          </>
        ) : (
          <>
            <dt>Serve a file at this exact URL</dt>
            <dd>
              <code className="ds-wav-code">{verification.well_known_url}</code>
            </dd>
            <dt>Containing exactly this content</dt>
            <dd>
              <code className="ds-wav-code">{verification.file_content}</code>
            </dd>
          </>
        )}
      </dl>

      <span className={`ds-wav-status ds-wav-status-${verification.status}`}>
        {verification.status === "pending" && "Not yet verified"}
        {verification.status === "verified" && "✓ Verified"}
        {verification.status === "failed" && "✗ Verification failed"}
      </span>
      <Button onClick={checkNow} disabled={busy}>
        {busy ? "Checking…" : "Check now"}
      </Button>
      {verification.last_error && verification.status !== "verified" && (
        <p className="ds-wav-last-error">{verification.last_error}</p>
      )}
      {verification.status === "verified" && (
        <p className="small muted" style={{ marginTop: "0.75rem" }}>
          This re-checks the moment any DAST campaign starts (plan §22.4) -- a passing check here
          isn&apos;t cached indefinitely.{" "}
          <Link href={`/app/projects/${verification.asset_id}/campaigns`}>
            Start a DAST campaign →
          </Link>
        </p>
      )}
    </div>
  );
}
