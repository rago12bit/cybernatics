"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, clearToken, getScan, getToken, wsUrl } from "./api";
import { isTerminal } from "./format";
import type { ProgressEvent, ScanView, ToolStatus } from "./types";

export type Connection = "connecting" | "live" | "polling" | "done";

/**
 * Live scan state: an initial REST read, a WebSocket for progress events, and a polling fallback if
 * the socket cannot be used. The database (REST) is the source of truth; events only make the UI
 * responsive, so every terminal event triggers a re-fetch instead of trusting the event payload.
 */
export function useScan(id: string) {
  const [scan, setScan] = useState<ScanView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [connection, setConnection] = useState<Connection>("connecting");
  const [version, setVersion] = useState(0); // bumps when results may have changed
  const alive = useRef(true);

  const refresh = useCallback(async () => {
    try {
      const s = await getScan(id);
      if (!alive.current) return null;
      setScan(s);
      setError(null);
      setVersion((v) => v + 1);
      return s;
    } catch (e) {
      if (!alive.current) return null;
      if (e instanceof ApiError && e.status === 401) clearToken();
      setError(e instanceof Error ? e.message : "Failed to load scan");
      return null;
    }
  }, [id]);

  useEffect(() => {
    alive.current = true;
    let ws: WebSocket | null = null;
    let poll: ReturnType<typeof setInterval> | null = null;

    const startPolling = () => {
      if (poll) return;
      setConnection("polling");
      poll = setInterval(async () => {
        const s = await refresh();
        if (s && isTerminal(s.status) && poll) {
          clearInterval(poll);
          poll = null;
          setConnection("done");
        }
      }, 3000);
    };

    (async () => {
      const first = await refresh();
      if (!alive.current || !first) return;
      if (isTerminal(first.status)) return setConnection("done");
      try {
        ws = new WebSocket(wsUrl(id));
      } catch {
        return startPolling();
      }
      ws.onopen = () => ws?.send(JSON.stringify({ token: getToken() ?? "" }));
      ws.onmessage = (m) => {
        let ev: ProgressEvent;
        try {
          ev = JSON.parse(String(m.data)) as ProgressEvent;
        } catch {
          return;
        }
        setConnection("live");
        if (ev.type === "tool.finished") {
          const { tool, type: _t, ...rest } = ev;
          setScan((s) =>
            s
              ? { ...s, status: "running", tool_status: { ...s.tool_status, [tool]: { ...s.tool_status[tool], ...rest } as ToolStatus } }
              : s,
          );
        } else if (ev.type === "scan.finished") {
          void refresh().then(() => setConnection("done"));
        }
      };
      ws.onerror = () => startPolling();
      ws.onclose = (e) => {
        if (alive.current && e.code !== 1000) startPolling();
      };
    })();

    return () => {
      alive.current = false;
      ws?.close();
      if (poll) clearInterval(poll);
    };
  }, [id, refresh]);

  return { scan, error, connection, version };
}
