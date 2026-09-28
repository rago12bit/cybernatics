"use client";

/* Novice and expert mode (plan §30.4): a per-viewer setting, not a per-user one (no real per-user
 * identity/settings backend exists yet — see docs/v2-week33-verification.md's "what Week 33 does
 * not claim"). Persisted in localStorage as a stand-in, same honest simplification the API token
 * already uses (sessionStorage). Controls what this session's own instructions ask for concretely:
 * row density, the plain-language explanation's default state, and whether rule ids/raw output are
 * shown or one click away. It does NOT change the landing page after sign-in — there is no
 * per-user sign-in flow to hang that on yet. */
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

export type Mode = "novice" | "expert";
const KEY = "bulwark.mode";

function readMode(): Mode {
  try {
    const v = localStorage.getItem(KEY);
    return v === "expert" ? "expert" : "novice";
  } catch {
    return "novice";
  }
}

const ModeContext = createContext<{ mode: Mode; setMode: (m: Mode) => void }>({
  mode: "novice",
  setMode: () => {},
});

export function ModeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<Mode>("novice");
  useEffect(() => setModeState(readMode()), []);
  const setMode = (m: Mode) => {
    setModeState(m);
    try {
      localStorage.setItem(KEY, m);
    } catch {
      /* storage unavailable: the choice just doesn't survive a reload */
    }
  };
  return <ModeContext.Provider value={{ mode, setMode }}>{children}</ModeContext.Provider>;
}

export function useMode(): { mode: Mode; setMode: (m: Mode) => void } {
  return useContext(ModeContext);
}
