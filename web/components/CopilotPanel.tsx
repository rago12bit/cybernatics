"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { ApiError, listCopilotMessages, postCopilotMessage, startCopilotConversation } from "@/lib/api";
import type { Citation, CopilotMessage } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./copilot-panel.css";

function CitationLink({ assetId, citation, i }: { assetId: string; citation: Citation; i: number }) {
  if (citation.kind === "issue" && citation.issue_id) {
    return (
      <Link key={i} href={`/app/projects/${assetId}/issues/${citation.issue_id}`} className="ds-copilot-citation">
        {citation.issue_id}
      </Link>
    );
  }
  // Code citations have nowhere to jump to yet -- this frontend has no jump-to-line view -- so
  // they render as plain text rather than a link that goes nowhere.
  return (
    <span key={i} className="ds-copilot-citation ds-copilot-citation-code">
      {citation.path}
      {citation.line ? `:${citation.line}` : ""}
    </span>
  );
}

export function CopilotPanel({
  assetId,
  context,
}: {
  assetId: string;
  context?: { context_kind: "issue" | "scan"; context_id: string };
}) {
  const [open, setOpen] = useState(false);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [messages, setMessages] = useState<CopilotMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [messages]);

  async function ensureConversation(): Promise<string> {
    if (conversationId) return conversationId;
    const conv = await startCopilotConversation(assetId, context);
    setConversationId(conv.id);
    const history = await listCopilotMessages(assetId, conv.id);
    setMessages(history);
    return conv.id;
  }

  async function openPanel() {
    setOpen(true);
    if (conversationId || busy) return;
    setBusy(true);
    setError(null);
    try {
      await ensureConversation();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not start a conversation");
    } finally {
      setBusy(false);
    }
  }

  async function send() {
    const question = input.trim();
    if (!question || busy) return;
    setInput("");
    setBusy(true);
    setError(null);
    const optimistic: CopilotMessage = {
      id: `pending-${Date.now()}`, role: "user", content: question, citations: null,
      created_at: new Date().toISOString(),
    }; // fmt: skip
    setMessages((m) => [...m, optimistic]);
    try {
      const convId = await ensureConversation();
      const answer = await postCopilotMessage(assetId, convId, question);
      setMessages((m) => [...m, answer]);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the copilot");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button className="ds-copilot-trigger" onClick={openPanel} aria-label="Open the copilot">
        Copilot
      </button>
      {open && (
        <div className="ds-copilot-panel" role="dialog" aria-label="Security copilot">
          <div className="ds-copilot-head">
            <span className="ds-copilot-title">Copilot</span>
            <button className="ds-copilot-close" onClick={() => setOpen(false)} aria-label="Close">
              ×
            </button>
          </div>

          <div className="ds-copilot-messages" ref={listRef}>
            {messages.length === 0 && !busy && (
              <p className="small muted">Ask about this project's issues, code, or routes.</p>
            )}
            {messages.map((m) => (
              <div key={m.id} className={`ds-copilot-msg ds-copilot-msg-${m.role}`}>
                <p>{m.content}</p>
                {m.citations && m.citations.length > 0 && (
                  <p className="ds-copilot-citations">
                    {m.citations.map((c, i) => (
                      <CitationLink key={i} assetId={assetId} citation={c} i={i} />
                    ))}
                  </p>
                )}
              </div>
            ))}
          </div>

          {error && <p className="ds-copilot-error" role="alert">{error}</p>}

          <div className="ds-copilot-input">
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && send()}
              placeholder="Ask a question…"
              disabled={busy}
            />
            <Button onClick={send} disabled={busy || !input.trim()}>
              {busy ? "…" : "Send"}
            </Button>
          </div>
        </div>
      )}
    </>
  );
}
