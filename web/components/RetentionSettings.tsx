"use client";

import { useEffect, useState } from "react";
import { ApiError, getRetentionSettings, saveRetentionSettings } from "@/lib/api";
import type { RetentionSettings as RetentionSettingsData } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./retention-settings.css";

export function RetentionSettings() {
  const [settings, setSettings] = useState<RetentionSettingsData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [draftDays, setDraftDays] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    getRetentionSettings().then(
      (s) => {
        setSettings(s);
        setDraftDays(String(s.retention_days));
      },
      (e) => setError(e instanceof ApiError ? e.message : "Failed to load"),
    );
  }, []);

  async function save() {
    const days = Number(draftDays);
    if (!Number.isInteger(days) || days < 1) {
      setError("Retention must be a whole number of days, at least 1.");
      return;
    }
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      setSettings(await saveRetentionSettings(days));
      setSaved(true);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not save");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="ds-retention">
      <p className="small muted ds-retention-intro">
        How long a scan&apos;s encrypted code snapshot and raw tool output are kept before being
        permanently destroyed (crypto-shredding, plan §22.2) -- issues and findings are never
        affected by this setting and are kept regardless.
      </p>

      {error && <p className="ds-retention-error" role="alert">{error}</p>}

      {settings === null ? (
        <p className="small muted">Loading…</p>
      ) : (
        <div className="ds-retention-form">
          <label className="ds-retention-label" htmlFor="retention-days">
            Delete a scan&apos;s encrypted data after
          </label>
          <div className="ds-retention-row">
            <input
              id="retention-days"
              type="number"
              min={1}
              step={1}
              value={draftDays}
              onChange={(e) => {
                setDraftDays(e.target.value);
                setSaved(false);
              }}
            />
            <span>days</span>
            <Button variant="primary" onClick={save} disabled={saving}>
              {saving ? "Saving…" : "Save"}
            </Button>
          </div>
          {saved && <p className="ds-retention-saved">Saved.</p>}
        </div>
      )}
    </div>
  );
}
