"use client";

import { useEffect, useState } from "react";
import { ApiError, clearToken, getScan, getToken, wsUrl } from "./api";
import { isTerminal } from "./format";
import type { ProgressEvent, ScanView, ToolStatus } from "./types";

export type Connection = "connecting" | "live" | "polling" | "done";

const POLL_MS = 3000;
const EXPIRED = "Your session expired. Sign in again.";

/**
 * Live scan state: an initial REST read, a WebSocket for progress events, and polling if the socket
 * cannot be used. The database (REST) is the source of truth; events only make the UI responsive, so
 * a terminal event triggers a re-fetch instead of trusting the payload. Whatever happens to the socket
 * (clean close, error, missed event), an unfinished scan keeps being polled until it finishes.
 */
export function useScan(id: string) {
  const [scan, setScan] = useState<ScanView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [connection, setConnection] = useState<Connection>("connecting");
  const [version, setVersion] = useState(0); // bumps only when the findings may have changed

  useEffect(() => {
    // Everything below belongs to THIS id. A late response for a previous id must never leak in.
    let cancelled = false;
    let ws: WebSocket | null = null;
    let poll: ReturnType<typeof setInterval> | null = null;
    let finished = false;
    let signature = "";
    setScan(null);
    setError(null);
    setConnection("connecting");

    const stopPolling = () => {
      if (poll) clearInterval(poll);
      poll = null;
    };
    const finish = () => {
      finished = true;
      stopPolling();
      setConnection("done");
    };
    const unauthorized = () => {
      finished = true;
      stopPolling();
      ws?.close();
      clearToken(); // the app returns to the sign-in screen
      setError(EXPIRED);
    };
    const accept = (s: ScanView) => {
      setScan(s);
      setError(null);
      const sig = `${s.status}|${s.unique_findings}`;
      if (sig !== signature) {
        signature = sig;
        setVersion((v) => v + 1);
      }
    };
    const refresh = async (): Promise<ScanView | null> => {
      try {
        const s = await getScan(id);
        if (cancelled) return null;
        accept(s);
        return s;
      } catch (e) {
        if (cancelled) return null;
        if (e instanceof ApiError && e.status === 401) unauthorized();
        else setError(e instanceof Error ? e.message : "Failed to load scan");
        return null;
      }
    };
    const startPolling = () => {
      if (poll || finished) return;
      setConnection("polling");
      poll = setInterval(async () => {
        const s = await refresh();
        if (s && isTerminal(s.status)) finish();
      }, POLL_MS);
    };

    (async () => {
      const first = await refresh();
      if (cancelled || !first) return;
      if (isTerminal(first.status)) return finish();
      try {
        ws = new WebSocket(wsUrl(id));
      } catch {
        return startPolling();
      }
      ws.onopen = () => ws?.send(JSON.stringify({ token: getToken() ?? "" }));
      ws.onmessage = (m) => {
        if (cancelled || finished) return;
        let ev: ProgressEvent;
        try {
          ev = JSON.parse(String(m.data)) as ProgressEvent;
        } catch {
          return;
        }
        setConnection("live");
        if (ev.type === "snapshot") {
          // The server's view at subscribe time. It may already be final (the scan can finish between
          // our first read and the socket connecting), so treat it as authoritative.
          if (isTerminal(ev.status)) void refresh().then((s) => s && finish());
        } else if (ev.type === "tool.finished") {
          const { tool, type: _t, ...rest } = ev;
          setScan((s) =>
            s
              ? { ...s, status: "running", tool_status: { ...s.tool_status, [tool]: { ...s.tool_status[tool], ...rest } as ToolStatus } }
              : s,
          );
        } else if (ev.type === "scan.finished") {
          finished = true; // the close that follows is expected
          void refresh().then(() => finish());
        }
      };
      ws.onerror = () => startPolling();
      ws.onclose = (e) => {
        if (cancelled || finished) return;
        if (e.code === 4401) return unauthorized();
        if (e.code === 4404) return setError("That scan no longer exists.");
        startPolling(); // any other close before the scan finished: fall back to polling
      };
    })();

    return () => {
      cancelled = true;
      ws?.close();
      stopPolling();
    };
  }, [id]);

  return { scan, error, connection, version };
}
