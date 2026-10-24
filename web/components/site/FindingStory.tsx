"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { shortPrint, SOURCE, STORY } from "@/lib/finding-story";

/* "Follow one finding": a real SQL injection from two scanners to a verified fix, one step per screen.
   The diagram pins beside the steps and lights the stage being read (an IntersectionObserver picks the
   step at the middle of the viewport). Without JavaScript, or on a phone, the steps simply read in
   order. Colours and states are classes, never inline styles (the strict CSP). */

const fp = shortPrint(STORY.fingerprint);
const [bandit, semgrep] = STORY.reports as [(typeof STORY.reports)[number], (typeof STORY.reports)[number]];

type Step = { title: string; node: [string, string]; body: ReactNode; artifact: { name: string; code: ReactNode }; src: string };

const STEPS: Step[] = [
  {
    title: "Two scanners, two reports",
    node: ["01 · two reports", `${STORY.path}:6 and :7`],
    body: (
      <p>
        Bandit flags line 6, where untrusted input is concatenated into SQL (<code>{bandit.rule}</code>, {bandit.severity}).
        Semgrep flags line 7, where the query runs (<code>{semgrep.rule}</code>, {semgrep.severity}). Run separately, that
        is two alerts for one bug, on two different scales.
      </p>
    ),
    artifact: {
      name: STORY.path,
      code: (
        <>
          {SOURCE.map(([n, line]) => (
            <span key={n} className="ln-row"><span className="c">{n}  </span><span className="n">{line}</span>{n === 6 ? <span className="k">   ← bandit {bandit.rule}</span> : n === 7 ? <span className="k">   ← semgrep</span> : null}{"\n"}</span>
          ))}
        </>
      ),
    },
    src: "core/sandbox/docker_runtime.py · core/adapters/",
  },
  {
    title: "One shape",
    node: ["02 · one shape", `${STORY.cwe.join(", ")} · ${STORY.owasp.join(", ")} · ${STORY.severity}`],
    body: (
      <p>
        Both reports become the same shape: where it is, what it is, and how bad each tool said it was, mapped onto one
        scale. Bandit&apos;s MEDIUM stays MEDIUM; Semgrep&apos;s ERROR is HIGH; the finding keeps the higher, {STORY.severity}.
        The mapping is a published table, not a hidden judgement.
      </p>
    ),
    artifact: {
      name: "finding (excerpt)",
      code: (
        <>
          <span className="n">{"{"}</span>{"\n"}
          {"  "}<span className="s">&quot;cwe&quot;</span>: <span className="n">{JSON.stringify(STORY.cwe)}</span>,{"\n"}
          {"  "}<span className="s">&quot;owasp_top_10_2021&quot;</span>: <span className="n">{JSON.stringify(STORY.owasp)}</span>,{"\n"}
          {"  "}<span className="s">&quot;native_severity&quot;</span>: <span className="n">{`{ "bandit": "${bandit.severity}", "semgrep": "${semgrep.severity}" }`}</span>,{"\n"}
          {"  "}<span className="s">&quot;normalized_severity&quot;</span>: <span className="k">&quot;{STORY.severity}&quot;</span>{"\n"}
          <span className="n">{"}"}</span>
        </>
      ),
    },
    src: "core/models/finding.py · docs/severity-matrix.md",
  },
  {
    title: "Merged, and you can see why",
    node: ["03 · one finding", `${STORY.agreement} scanners · ${fp}`],
    body: (
      <p>
        Same file, the same weakness, lines within three of each other, and code that matches: one defect. Bulwark keeps one
        finding that names both scanners, and gives it a fingerprint that stays the same when the code around it moves.
      </p>
    ),
    artifact: {
      name: "correlation",
      code: (
        <>
          <span className="c">same file      </span><span className="n">{STORY.path}</span>{"\n"}
          <span className="c">same weakness  </span><span className="n">{STORY.cwe.join(", ")}</span>{"\n"}
          <span className="c">lines          </span><span className="n">6 and 7 (within 3)</span>{"\n"}
          <span className="c">reported_by    </span><span className="k">{STORY.reportedBy.join(", ")}</span>{"\n"}
          <span className="c">fingerprint    </span><span className="s">{fp}</span>
        </>
      ),
    },
    src: "core/correlation/engine.py",
  },
  {
    title: "Ranked by risk, not by count",
    node: ["04 · ranked", `risk ${STORY.riskScore} / 100`],
    body: (
      <p>
        Severity, how many independent scanners agree, and, for a package, the chance of exploitation (EPSS) and known
        exploitation (CISA KEV) set its place in the queue. Each project can weigh these differently; context such as
        &ldquo;not exposed to the internet&rdquo; can only lower a priority.
      </p>
    ),
    artifact: {
      name: "scoring",
      code: (
        <>
          <span className="s">&quot;risk_score&quot;</span>: <span className="k">{STORY.riskScore}</span>,{"\n"}
          <span className="s">&quot;risk_factors&quot;</span>: [{"\n"}
          {STORY.riskFactors.map((f, i) => (
            <span key={f}>{"  "}<span className="n">&quot;{f}&quot;</span>{i < STORY.riskFactors.length - 1 ? "," : ""}{"\n"}</span>
          ))}
          ]
        </>
      ),
    },
    src: "core/scoring/ · core/priority/engine.py",
  },
  {
    title: "Tracked until it is gone",
    node: ["05 · tracked", "Issue · SLA · ticket"],
    body: (
      <p>
        The finding becomes an Issue, keyed by its fingerprint, so the next scan updates it rather than adding another. Its
        SLA clock starts at first detection and, if the project files tickets, one in Jira or GitHub Issues follows it both
        ways.
      </p>
    ),
    artifact: {
      name: "issue",
      code: (
        <>
          <span className="c">state      </span><span className="n">open · first seen {STORY.scannedOn}</span>{"\n"}
          <span className="c">key        </span><span className="s">{fp}</span>{"\n"}
          <span className="c">SLA        </span><span className="n">{STORY.severity}: fix within 30 days (starter policy)</span>{"\n"}
          <span className="c">ticket     </span><span className="n">Jira or GitHub Issues, both ways</span>
        </>
      ),
    },
    src: "core/issues.py · core/sla/ · core/tickets/",
  },
  {
    title: "Fixed, and checked",
    node: ["06 · fixed", "targeted retest · Issue fixed"],
    body: (
      <p>
        A developer marks it ready for retest. A targeted retest re-runs only the check that found it, against only that file.
        If it no longer fires, the Issue is fixed; if a later scan finds it again, it reopens as reintroduced.
      </p>
    ),
    artifact: {
      name: "a fix like this",
      code: (
        <>
          <span className="del">-    query = &quot;SELECT * FROM users WHERE id=&quot; + user_id</span>{"\n"}
          <span className="del">-    return conn.execute(query).fetchall()</span>{"\n"}
          <span className="add">+    return conn.execute(text(&quot;SELECT * FROM users WHERE id = :id&quot;),</span>{"\n"}
          <span className="add">+                        {"{"}&quot;id&quot;: user_id{"}"}).fetchall()</span>
        </>
      ),
    },
    src: "core/retest/targeted.py · core/retest/service.py",
  },
];

// The diagram's boxes, top to bottom. Step 0 is the two scanner boxes side by side.
const Y = [16, 136, 250, 364, 478, 592];

function Node({ i, step, x, y, w, label, value }: { i: number; step: number; x: number; y: number; w: number; label: string; value: string }) {
  const state = i < step ? "done" : i === step ? "on" : "next";
  return (
    <g className={`fs-node ${state}`}>
      <rect x={x} y={y} width={w} height={64} strokeWidth="1" />
      <text className="t-mono" x={x + 14} y={y + 24} fontSize="10.5">{label}</text>
      <text className="t-mono t-bright t-nocase" x={x + 14} y={y + 46} fontSize="12">{value}</text>
    </g>
  );
}

function Diagram({ step }: { step: number }) {
  const edge = (i: number) => (i <= step ? "fs-edge lit" : "fs-edge");
  return (
    <svg className="art-svg fs-svg" viewBox="0 0 420 672" role="img" aria-label={`Step ${step + 1} of ${STEPS.length}: ${STEPS[step]!.title}`}>
      <path className={edge(1)} d="M108 80V108H210V136M312 80V108H210" strokeWidth="1.2" />
      {[2, 3, 4, 5].map((i) => <path key={i} className={edge(i)} d={`M210 ${Y[i - 1]! + 64}V${Y[i]}`} strokeWidth="1.2" />)}
      <Node i={0} step={step} x={16} y={Y[0]!} w={184} label={`bandit · ${bandit.rule}`} value={`${STORY.path.split("/").pop()}:6`} />
      <Node i={0} step={step} x={220} y={Y[0]!} w={184} label="semgrep · raw query" value={`${STORY.path.split("/").pop()}:7`} />
      {STEPS.slice(1).map((s, k) => (
        <Node key={s.title} i={k + 1} step={step} x={50} y={Y[k + 1]!} w={320} label={s.node[0]} value={s.node[1]} />
      ))}
    </svg>
  );
}

export function FindingStory() {
  const [step, setStep] = useState(0);
  const list = useRef<HTMLOListElement>(null);

  useEffect(() => {
    const items = Array.from(list.current?.querySelectorAll<HTMLElement>("[data-step]") ?? []);
    if (!items.length || typeof IntersectionObserver === "undefined") return; // progressive enhancement
    const io = new IntersectionObserver(
      (entries) => entries.forEach((e) => e.isIntersecting && setStep(Number((e.target as HTMLElement).dataset.step))),
      { rootMargin: "-45% 0px -50% 0px" },
    );
    items.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, []);

  return (
    <section className="section story" id="story" aria-labelledby="story-h">
      <div className="sec-head">
        <div className="stack">
          <span className="eyebrow">Follow one finding</span>
          <h2 id="story-h">One SQL injection, from two alerts to a verified fix</h2>
          <p className="lede">
            A real scan of the test fixture <code>tests/fixtures/vuln-py</code>, on <time dateTime={STORY.scannedOn} className="nowrap">{STORY.scannedOn}</time>. Every value below is from
            that scan; only the fix in the last step is an example.
          </p>
        </div>
      </div>
      <div className="story-grid">
        <ol className="story-steps" ref={list}>
          {STEPS.map((s, i) => (
            <li key={s.title} data-step={i} className={i === step ? "on" : undefined}>
              <span className="story-n" aria-hidden="true">{String(i + 1).padStart(2, "0")}</span>
              <h3>{s.title}</h3>
              {s.body}
              <div className="codewin">
                <header><span className="dots" aria-hidden="true"><i /><i /><i /></span><span className="name">{s.artifact.name}</span></header>
                <pre tabIndex={0} aria-label={`${s.title}: ${s.artifact.name}`}><code>{s.artifact.code}</code></pre>
              </div>
              <span className="src">{s.src}</span>
            </li>
          ))}
        </ol>
        <div className="story-pin" aria-hidden="true">
          <div className="solution">
            <div className="panel-head"><span className="eyebrow plain">One finding</span><span className="label">{step + 1} / {STEPS.length}</span></div>
            <div className="grid-bg"><Diagram step={step} /></div>
          </div>
        </div>
      </div>
    </section>
  );
}
