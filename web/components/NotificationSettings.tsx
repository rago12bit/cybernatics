"use client";

import { useEffect, useId, useState } from "react";
import {
  ApiError, getMyNotificationPrefs, getTeamNotificationPrefs, saveMyNotificationPrefs, saveTeamNotificationPrefs,
} from "@/lib/api";
import type { NotificationPrefsView } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./automation.css";

/** Plan §49: "notification preferences per event and per channel (in-app, email, Slack, Teams,
 * webhook), with a daily digest option so notifications don't become noise." Yours: in-app and
 * email. The team's: Slack, Discord, Teams and the webhook together, for each kind of event. */

const MODE_WORD: Record<string, string> = { off: "Off", instant: "At once", digest: "Daily digest" };
const CHANNEL_WORD: Record<string, string> = { in_app: "In the app", email: "Email", team: "Team channels" };

function Matrix({ view, modes, onChange, label }: {
  view: NotificationPrefsView; modes: Record<string, Record<string, string>>;
  onChange: (kind: string, channel: string, mode: string) => void; label: string;
}) {
  const channels = Object.keys(view.channels);
  return (
    <table className="ds-au-table ds-np-table">
      <caption className="ds-np-caption">{label}</caption>
      <thead>
        <tr><th scope="col">When</th>{channels.map((c) => <th key={c} scope="col">{CHANNEL_WORD[c] ?? c}</th>)}</tr>
      </thead>
      <tbody>
        {view.kinds.map((k) => (
          <tr key={k.key}>
            <th scope="row">{k.label}</th>
            {channels.map((c) => (
              <td key={c}>
                <select aria-label={`${k.label}: ${CHANNEL_WORD[c] ?? c}`} value={modes[k.key]?.[c] ?? k.modes[c]}
                        onChange={(e) => onChange(k.key, c, e.target.value)}>
                  {view.channels[c]!.map((m) => <option key={m} value={m}>{MODE_WORD[m] ?? m}</option>)}
                </select>
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function usePrefs(load: () => Promise<NotificationPrefsView>) {
  const [view, setView] = useState<NotificationPrefsView | null>(null);
  const [modes, setModes] = useState<Record<string, Record<string, string>>>({});
  const [hour, setHour] = useState(8);
  const [email, setEmail] = useState("");
  useEffect(() => {
    load().then((v) => {
      if (!Array.isArray(v?.kinds)) return;
      setView(v);
      setModes(Object.fromEntries(v.kinds.map((k) => [k.key, { ...k.modes }])));
      setHour(v.digest_hour);
      setEmail(v.email ?? "");
    }, () => setView(null));
  }, [load]);
  return { view, setView, modes, setModes, hour, setHour, email, setEmail };
}

const HOURS = Array.from({ length: 24 }, (_, h) => h);

export function NotificationSettings() {
  const fid = useId();
  const mine = usePrefs(getMyNotificationPrefs);
  const team = usePrefs(getTeamNotificationPrefs);
  const [status, setStatus] = useState<{ which: string; ok: boolean; text: string } | null>(null);

  async function save(which: "mine" | "team") {
    setStatus(null);
    try {
      if (which === "mine") {
        mine.setView(await saveMyNotificationPrefs({ modes: mine.modes, digest_hour: mine.hour, email: mine.email.trim() || null }));
      } else {
        team.setView(await saveTeamNotificationPrefs({ modes: team.modes, digest_hour: team.hour }));
      }
      setStatus({ which, ok: true, text: "Saved." });
    } catch (e) {
      setStatus({ which, ok: false, text: e instanceof ApiError ? e.message : "Could not save." });
    }
  }
  const change = (p: typeof mine) => (kind: string, channel: string, mode: string) =>
    p.setModes((m) => ({ ...m, [kind]: { ...(m[kind] ?? {}), [channel]: mode } }));

  return (
    <div className="ds-au ds-np">
      <h1>Notifications</h1>
      {mine.view && (
        <section aria-labelledby={`${fid}-mine`}>
          <h2 id={`${fid}-mine`}>Yours</h2>
          {mine.view.person === false ? (
            <p>You are signed in with the shared token, which is nobody. Sign in with a personal token to choose your notifications.</p>
          ) : (
            <>
              <Matrix view={mine.view} modes={mine.modes} onChange={change(mine)} label="What reaches you, and how" />
              <div className="ds-ed-row">
                <label htmlFor={`${fid}-email`}>Email address</label>
                <input id={`${fid}-email`} type="email" value={mine.email} onChange={(e) => mine.setEmail(e.target.value)} placeholder="you@example.com" />
                {!mine.view.email_available && <p className="ds-au-meta">No mail server is set up on this Bulwark (BULWARK_SMTP_HOST), so nothing is emailed yet.</p>}
              </div>
              <div className="ds-ed-row">
                <label htmlFor={`${fid}-hour`}>Daily digest at (UTC)</label>
                <select id={`${fid}-hour`} value={mine.hour} onChange={(e) => mine.setHour(Number(e.target.value))}>
                  {HOURS.map((h) => <option key={h} value={h}>{String(h).padStart(2, "0")}:00</option>)}
                </select>
              </div>
              {status?.which === "mine" && <p role={status.ok ? "status" : "alert"} className={status.ok ? "ds-au-meta" : "ds-au-error"}>{status.text}</p>}
              <div className="ds-au-actions"><Button variant="primary" onClick={() => save("mine")}>Save yours</Button></div>
            </>
          )}
        </section>
      )}
      {team.view && (
        <section aria-labelledby={`${fid}-team`}>
          <h2 id={`${fid}-team`}>The team channels</h2>
          <p className="ds-au-meta">Slack, Discord, Microsoft Teams and the outbound webhook, wherever they are configured. Changing these needs scans:write.</p>
          <Matrix view={team.view} modes={team.modes} onChange={change(team)} label="What the team channels hear, and when" />
          <div className="ds-ed-row">
            <label htmlFor={`${fid}-thour`}>Team digest at (UTC)</label>
            <select id={`${fid}-thour`} value={team.hour} onChange={(e) => team.setHour(Number(e.target.value))}>
              {HOURS.map((h) => <option key={h} value={h}>{String(h).padStart(2, "0")}:00</option>)}
            </select>
          </div>
          {status?.which === "team" && <p role={status.ok ? "status" : "alert"} className={status.ok ? "ds-au-meta" : "ds-au-error"}>{status.text}</p>}
          <div className="ds-au-actions"><Button onClick={() => save("team")}>Save the team&apos;s</Button></div>
        </section>
      )}
    </div>
  );
}
