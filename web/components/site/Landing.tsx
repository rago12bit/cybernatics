import Link from "next/link";
import { API_URL } from "@/lib/api";
import { BENCHMARK } from "@/lib/benchmark";
import { Blueprint, DedupChart, DedupDiagram, PipelineDiagram, StepChart, Stripes } from "./graphics";
import { StackSection } from "./StackSection";
import { Scanners } from "./Scanners";

const pct = (n: number, d = 1) => `${(n * 100).toFixed(d)}%`;
const fmt = (n: number) => n.toLocaleString("en-US");

export function Landing() {
  const max = Math.max(...BENCHMARK.rawPerScanner.map((s) => s.raw));
  return (
    <div className="page">
      {/* ---- Hero ---- */}
      <StackSection index={0}>
      <section className="section hero" id="product">
        <div className="hero-copy">
          <span className="eyebrow">Security scanning platform</span>
          <h1 className="display">Security scanning, without the noise.</h1>
          <p className="lede">
            Bulwark runs best-in-class open-source scanners in locked-down containers, merges their overlapping
            results into one report, and shows you which scanners agree.
          </p>
          <div className="hero-actions">
            <Link href="/app" className="btn primary">Open the app →</Link>
            <Link href="#results" className="btn">See the results</Link>
          </div>
          <p className="label dimmed">5 scanners · sandboxed · {pct(BENCHMARK.dedupRate)} fewer findings</p>
        </div>
        <div className="hero-art">
          <div className="solution">
            <div className="panel-head"><span className="eyebrow plain">Cross-tool dedup</span><span className="label">The solution</span></div>
            <div className="grid-bg">
              <div className="brackets" aria-hidden="true"><i /><i /><i /><i /></div>
              <DedupDiagram />
            </div>
          </div>
        </div>
      </section>
      </StackSection>

      {/* ---- Feature grid ---- */}
      <StackSection index={1}>
        <section className="section" aria-labelledby="more-h">
          <div className="sec-head">
            <h2 id="more-h">Do more with Bulwark</h2>
            <div className="actions">
              <Link href="/app" className="btn primary sm">Try Bulwark →</Link>
              <a href={`${API_URL}/docs`} className="btn sm">API reference</a>
            </div>
          </div>
          <div className="feature-grid">
            <div className="code-cell">
              <div className="codewin">
                <header><span className="dots" aria-hidden="true"><i /><i /><i /></span><span className="name">bulwark scan</span></header>
                <pre><code><span className="c"># a public repo, folder or .zip</span>{"\n"}<span className="k">$</span> <span className="n">bulwark scan</span> <span className="s">https://github.com/OWASP/NodeGoat</span>{"\n\n"}<span className="n">{"{"}</span>{"\n"}  <span className="s">&quot;tool_status&quot;</span>: <span className="n">{"{"} ... 5 scanners ok {"}"}</span>,{"\n"}  <span className="s">&quot;stats&quot;</span>: <span className="n">{"{"}</span>{"\n"}    <span className="s">&quot;raw_findings&quot;</span>: <span className="n">{BENCHMARK.repos[1]!.raw}</span>,{"\n"}    <span className="s">&quot;unique_findings&quot;</span>: <span className="n">{BENCHMARK.repos[1]!.unique}</span>,{"\n"}    <span className="s">&quot;dedup_rate&quot;</span>: <span className="n">{BENCHMARK.repos[1]!.dedup.toFixed(2)}</span>{"\n"}  <span className="n">{"}"}</span>,{"\n"}  <span className="s">&quot;findings&quot;</span>: <span className="n">[ ... ]</span>{"\n"}<span className="n">{"}"}</span></code></pre>
              </div>
              <div className="stack">
                <span className="label">One engine, several surfaces</span>
                <p className="small muted">The CLI is the engine. The API, this web app and (soon) editor and CI integrations are thin clients over it.</p>
              </div>
            </div>
            <div className="hatch" aria-hidden="true" />
            <div className="feature-cells">
              <div className="fcell"><div className="art"><Blueprint shape="a" uid="1" /></div><div className="txt"><span className="label">Sandboxed by default</span><p>Every scanner runs in its own container: no network, read-only filesystem, all capabilities dropped.</p></div></div>
              <div className="fcell"><div className="art"><Blueprint shape="b" uid="2" /></div><div className="txt"><span className="label">Partial results</span><p>One scanner timing out never fails the scan. You get the rest, plus a status for each.</p></div></div>
              <div className="fcell"><div className="art"><StepChart seed={3} /></div><div className="txt"><span className="label">Live progress</span><p>Watch each scanner report in over a WebSocket, with a polling fallback.</p></div></div>
              <div className="fcell half"><div className="art"><Blueprint shape="d" uid="4" /></div><div className="txt"><span className="label">Cross-tool deduplication</span><p>Bandit flags line 6, Semgrep line 7: one SQL injection. Bulwark merges them and shows exactly which scanners agree.</p></div></div>
              <div className="fcell half"><div className="art"><Blueprint shape="e" uid="5" /></div><div className="txt"><span className="label">Safe ingestion</span><p>Zip-slip and decompression-bomb guards, SSRF-checked Git URLs, and dependencies are never installed.</p></div></div>
            </div>
          </div>
        </section>
      </StackSection>

      {/* ---- Results ---- */}
      <StackSection index={2}>
        <section className="section metrics" id="results" aria-labelledby="results-h">
          <div className="metric-main">
            <div className="rule"><span className="eyebrow plain">Findings after merging</span></div>
            <div className="stack">
              <h2 id="results-h" className="big">{pct(BENCHMARK.dedupRate)}</h2>
              <p className="dedup-note">fewer findings across five public repositories: {fmt(BENCHMARK.raw)} raw reports became {fmt(BENCHMARK.unique)} unique ones.</p>
            </div>
            <DedupChart repos={BENCHMARK.repos} />
            <p className="small dim">Measured {BENCHMARK.measuredOn}. This measures duplicate reduction, not accuracy. Dependency-heavy repos overlap most; Terraform-only repos least.</p>
          </div>
          <div className="metric-side">
            <div>
              <span className="eyebrow plain">Raw findings by scanner</span>
              <div className="bars">
                {BENCHMARK.rawPerScanner.map((s) => (
                  <div key={s.tool} className="bar-row">
                    <div className="bar-head"><span>{s.tool}</span><span>{fmt(s.raw)}</span></div>
                    <div className="bar-track">
                      <div className={`bar-fill w-${Math.max(4, Math.round((s.raw / max) * 20) * 5)}`} />
                      <div className="bar-rest" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <span className="eyebrow plain">Robustness</span>
              <p className="numeral">5 / 5</p>
              <p className="small muted">repositories completed with no scanner failing or timing out.</p>
            </div>
          </div>
        </section>
      </StackSection>

      {/* ---- Scanners + pipeline ---- */}
      <StackSection index={3}>
        <section className="section ingredients" id="scanners" aria-labelledby="scan-h">
          <div className="cell stack">
            <span className="eyebrow">The scanners [05]</span>
            <h2 id="scan-h">Best-in-class open source, one pipeline</h2>
            <p className="lede">Detection is delegated to mature tools. Bulwark&apos;s contribution is normalisation and correlation, with risk-based prioritisation next.</p>
            <Scanners />
          </div>
          <div className="hero-art">
            <div className="solution">
              <div className="panel-head"><span className="eyebrow plain">How a scan flows</span><span className="label">The pipeline</span></div>
              <div className="grid-bg"><div className="brackets" aria-hidden="true"><i /><i /><i /><i /></div><PipelineDiagram /></div>
              <div className="panel-foot"><span>Bulwark</span><span>Sandboxed by default</span></div>
            </div>
          </div>
        </section>
      </StackSection>

      {/* ---- Shipped / roadmap ---- */}
      <StackSection index={4}>
        <section className="section stackrow" aria-label="Status">
          <div className="cell stack">
            <span className="eyebrow">What ships today</span>
            <h2>Built like a security tool</h2>
            <ul className="checklist">
              <li>Sandboxed scanner containers</li>
              <li>Cross-tool correlation and fingerprints</li>
              <li>REST + WebSocket API</li>
              <li>This web app and a CLI</li>
              <li>Strict CSP, text-only rendering of scanner data</li>
            </ul>
          </div>
          <div className="cell stack">
            <span className="eyebrow plain">Roadmap</span>
            <h2>Next: ranked by real risk</h2>
            <ul className="checklist">
              <li className="soon">EPSS + CISA KEV risk score</li>
              <li className="soon">Plain-English fixes, labelled as AI suggestions</li>
              <li className="soon">VS Code extension</li>
              <li className="soon">GitHub Action</li>
              <li className="soon">Signed reports and SBOMs</li>
            </ul>
          </div>
        </section>
      </StackSection>

      {/* ---- CTA + footer (the last panel slides over everything) ---- */}
      <StackSection index={5}>
      <section className="cta" aria-label="Get started">
        <Stripes seed={7} groups={16} rows={2} />
        <div className="cta-copy">
          <span className="eyebrow">Get started</span>
          <h2 className="display">Scan your first repo in a minute.</h2>
          <div className="hero-actions"><Link href="/app" className="btn primary">Open the app →</Link></div>
          <span className="tagline">[ Bulwark ] local-first / sandboxed_</span>
        </div>
      </section>
      <footer className="foot">
        <div className="foot-links">
          <div><h4>Product</h4><ul><li><Link href="/app">Open app</Link></li><li><Link href="/#results">Results</Link></li><li><Link href="/#scanners">Scanners</Link></li></ul></div>
          <div><h4>Developers</h4><ul><li><a href={`${API_URL}/docs`}>API reference</a></li><li>CLI: bulwark scan</li><li>WebSocket progress</li></ul></div>
          <div><h4>Security</h4><ul><li>Sandboxed runners</li><li>SSRF + zip-slip guards</li><li>Secret redaction</li></ul></div>
          <div><h4>Project</h4><ul><li>Apache-2.0</li><li>Open-source scanners</li><li>Benchmarks published</li></ul></div>
        </div>
        <Stripes seed={11} groups={16} rows={3} />
      </footer>
      </StackSection>
    </div>
  );
}
