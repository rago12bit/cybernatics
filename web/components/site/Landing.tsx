import Link from "next/link";
import { BENCHMARK } from "@/lib/benchmark";
import { counts } from "@/lib/catalogue";
import { APP_CTA, APP_HREF, DEMO_ONLY, DOCS_HREF } from "@/lib/site";
import { snippets } from "@/lib/snippets";
import { Blueprint, DedupChart, DedupDiagram, StepChart, Stripes } from "./graphics";
import { PlugIn } from "./PlugIn";
import { ProductFrame } from "./ProductFrame";
import { StackSection } from "./StackSection";
import { WhereItSits } from "./WhereItSits";
import { Recording } from "./Recording";
import { RepoScan } from "./RepoScan";
import { Scanners } from "./Scanners";
import { SiteFooter } from "./SiteFooter";
import { ScrollReveal } from "./ScrollReveal";
import { CountUp, Glow, Reveal, RiseText, ScrollProgress } from "./Motion";
import { widthClass } from "@/lib/recording";
import "./sections.css";

// Blocks on the home page that rise into view (the feature cells have their own Reveal).
const HOME_REVEAL = [
  ".reveal-me", ".rec-head", ".rec-half", ".feature-grid .code-cell > *", ".metric-main > *", ".metric-side > *",
  ".ingredients > *", ".wis-map > *", ".versus > *", ".plug-sec > *", ".pframe",
  // Not the status row or the closing panel: each slides up over the one before, so its text must already be
  // in place. Fading it in as well left the panel arriving empty and the words popping in afterwards.
].join(", ");

const pct = (n: number, d = 1) => `${(n * 100).toFixed(d)}%`;
const fmt = (n: number) => n.toLocaleString("en-US");

export function Landing() {
  const max = Math.max(...BENCHMARK.rawPerScanner.map((s) => s.raw));
  const confirmed = BENCHMARK.repos.reduce((n, r) => n + r.merged, 0); // findings reported by 2+ scanners
  const catalogue = counts(); // from the code's own registries (lib/integrations.json)
  return (
    <div className="page">
      <ScrollProgress />
      <ScrollReveal selector={HOME_REVEAL} />
      {/* ---- Hero ---- */}
      <StackSection index={0}>
      <section className="section hero" id="product">
        <div className="hero-copy">
          <div className="hero-main">
            <span className="eyebrow">Security scanning platform</span>
            <h1 className="display"><RiseText text="Security scanning, without the noise." /></h1>
            <p className="lede">
              Bulwark runs best-in-class open-source scanners in locked-down containers, merges their overlapping
              results into one report, and shows you which scanners agree.
            </p>
            <div className="hero-actions">
              <Link href={APP_HREF} className="btn primary">{APP_CTA}</Link>
              <Link href="/#recording" className="btn">See a recorded scan</Link>
            </div>
          </div>
          <div className="hero-stats">
            <div><span className="numeral"><CountUp value={catalogue.scanners} /></span><span className="label dimmed">Scanners, {catalogue.defaultScanners} by default</span></div>
            <div><span className="numeral"><CountUp value={catalogue.parsers} /></span><span className="label dimmed">Report formats to import</span></div>
            <div><span className="numeral"><CountUp value={0} /></span><span className="label dimmed">Network access in sandbox</span></div>
          </div>
        </div>
        <div className="hero-art">
          <Glow className="solution">
            <div className="panel-head"><span className="eyebrow plain">Cross-tool dedup</span><span className="label">The solution</span></div>
            <div className="grid-bg">
              <div className="brackets" aria-hidden="true"><i /><i /><i /><i /></div>
              <DedupDiagram />
            </div>
            <ul className="rail" aria-label="Scanners feeding the pipeline">
              {["bandit", "semgrep", "gitleaks", "trivy", "osv-scanner"].map((t) => <li key={t}>{t}</li>)}
            </ul>
          </Glow>
        </div>
      </section>
      </StackSection>

      {/* ---- The app itself, right under the headline ---- */}
      <StackSection index={1}>
        <section className="pframe-sec" id="app" aria-labelledby="app-h">
          <div className="pframe-head">
            <span className="eyebrow" id="app-h">The app</span>
            <p>Real screens of this build, on the recorded OWASP Juice Shop scan: the verdict, one issue, and every issue at once.</p>
            <Link href="/sample" className="btn sm">Explore the recorded scan →</Link>
          </div>
          <ProductFrame />
        </section>
      </StackSection>

      {/* ---- Scan a GitHub repository, after signing in ---- */}
      <StackSection index={2}>
        <RepoScan />
      </StackSection>

      {/* ---- The recorded scan (Week 77) ---- */}
      <StackSection index={3}>
        <Recording />
      </StackSection>

      {/* ---- Where it sits: what comes in, what goes out ---- */}
      <StackSection index={4}>
        <WhereItSits />
      </StackSection>

      {/* ---- Feature grid ---- */}
      <StackSection index={5}>
        <section className="section" aria-labelledby="more-h">
          <div className="sec-head">
            <h2 id="more-h">Do more with Bulwark</h2>
            <div className="actions">
              <Link href={APP_HREF} className="btn primary sm">{DEMO_ONLY ? "Run it yourself →" : "Try Bulwark →"}</Link>
              <a href={DOCS_HREF} className="btn sm">API reference</a>
            </div>
          </div>
          <div className="feature-grid">
            <div className="code-cell">
              <div className="codewin">
                <header><span className="dots" aria-hidden="true"><i /><i /><i /></span><span className="name">bulwark scan</span></header>
                <pre tabIndex={0} aria-label="bulwark scan output"><code><span className="c"># a public repo, folder or .zip</span>{"\n"}<span className="k">$</span> <span className="n">bulwark scan</span> <span className="s">https://github.com/OWASP/NodeGoat</span>{"\n\n"}<span className="n">{"{"}</span>{"\n"}  <span className="s">&quot;tool_status&quot;</span>: <span className="n">{"{"} ... 5 scanners ok {"}"}</span>,{"\n"}  <span className="s">&quot;stats&quot;</span>: <span className="n">{"{"}</span>{"\n"}    <span className="s">&quot;raw_findings&quot;</span>: <span className="n">{BENCHMARK.repos[1]!.raw}</span>,{"\n"}    <span className="s">&quot;unique_findings&quot;</span>: <span className="n">{BENCHMARK.repos[1]!.unique}</span>,{"\n"}    <span className="s">&quot;dedup_rate&quot;</span>: <span className="n">{BENCHMARK.repos[1]!.dedup.toFixed(2)}</span>{"\n"}  <span className="n">{"}"}</span>,{"\n"}  <span className="s">&quot;findings&quot;</span>: <span className="n">[ ... ]</span>{"\n"}<span className="n">{"}"}</span></code></pre>
              </div>
              <div className="codewin grow">
                <header><span className="dots" aria-hidden="true"><i /><i /><i /></span><span className="name">live progress · websocket</span></header>
                <pre tabIndex={0} aria-label="Live progress events"><code><span className="c"># one event per scanner, as it finishes</span>{"\n"}<span className="k">tool.finished</span>  <span className="n">gitleaks</span>     <span className="s">ok</span>  <span className="n">findings=1</span>{"\n"}<span className="k">tool.finished</span>  <span className="n">bandit</span>       <span className="s">ok</span>  <span className="n">findings=6</span>{"\n"}<span className="k">tool.finished</span>  <span className="n">osv-scanner</span>  <span className="s">ok</span>  <span className="n">findings=7</span>{"\n"}<span className="k">tool.finished</span>  <span className="n">trivy</span>        <span className="s">ok</span>  <span className="n">findings=8</span>{"\n"}<span className="k">tool.finished</span>  <span className="n">semgrep</span>      <span className="s">ok</span>  <span className="n">findings=1</span>{"\n"}<span className="k">scan.finished</span>  <span className="s">completed</span>  <span className="n">raw=23 unique=21</span></code></pre>
              </div>
              <div className="stack">
                <span className="label">One engine, several surfaces</span>
                <p className="small muted">The CLI is the engine. The API, this web app, the VS Code extension and the GitHub Action are all thin clients over it.</p>
              </div>
            </div>
            <div className="hatch" aria-hidden="true" />
            <div className="feature-cells">
              <Reveal glow className="fcell" delay={1}><div className="art"><Blueprint shape="a" uid="1" /></div><div className="txt"><span className="label">Sandboxed by default</span><p>Every scanner runs in its own container: no network, read-only filesystem, all capabilities dropped.</p></div></Reveal>
              <Reveal glow className="fcell" delay={2}><div className="art"><Blueprint shape="b" uid="2" /></div><div className="txt"><span className="label">Partial results</span><p>One scanner timing out never fails the scan. You get the rest, plus a status for each.</p></div></Reveal>
              <Reveal glow className="fcell" delay={3}><div className="art"><StepChart seed={3} /></div><div className="txt"><span className="label">Live progress</span><p>Watch each scanner report in over a WebSocket, with a polling fallback.</p></div></Reveal>
              <Reveal glow className="fcell half" delay={4}><div className="art"><Blueprint shape="d" uid="4" /></div><div className="txt"><span className="label">Cross-tool deduplication</span><p>Bandit flags line 6, Semgrep line 7: one SQL injection. Bulwark merges them and shows exactly which scanners agree.</p></div></Reveal>
              <Reveal glow className="fcell half" delay={5}><div className="art"><Blueprint shape="e" uid="5" /></div><div className="txt"><span className="label">Safe ingestion</span><p>Zip-slip and decompression-bomb guards, SSRF-checked Git URLs, and dependencies are never installed.</p></div></Reveal>
            </div>
          </div>
        </section>
      </StackSection>

      {/* ---- Results ---- */}
      <StackSection index={6}>
        <section className="section metrics" id="results" aria-labelledby="results-h">
          <div className="metric-main">
            <div className="rule"><span className="eyebrow plain">The same five scanners, the same five repositories</span></div>
            <h2 id="results-h" className="sr-only">{fmt(BENCHMARK.raw)} reports from the scanners run separately, {fmt(BENCHMARK.unique)} findings with Bulwark</h2>
            <div className="versus" aria-hidden="true">
              <div className="versus-row before">
                <div className="versus-who"><span className="label dimmed">Run separately</span><span className="versus-num"><CountUp value={BENCHMARK.raw} group /></span></div>
                <div className="versus-bar"><div className={`bar-fill ${widthClass(BENCHMARK.raw, BENCHMARK.raw)}`} /></div>
              </div>
              <div className="versus-row">
                <div className="versus-who"><span className="label">With Bulwark</span><span className="versus-num"><CountUp value={BENCHMARK.unique} group /></span></div>
                <div className="versus-bar"><div className={`bar-fill ${widthClass(BENCHMARK.unique, BENCHMARK.raw)}`} /><div className="bar-rest" /></div>
              </div>
            </div>
            <p className="dedup-note">
              <span className="versus-gap">{pct(BENCHMARK.dedupRate)} fewer to read.</span> Five scanners on five public repositories reported
              {" "}{fmt(BENCHMARK.raw)} alerts; merged, they are {fmt(BENCHMARK.unique)} findings, and {fmt(confirmed)} of those were confirmed by two
              or more scanners.
            </p>
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
            <div>
              <span className="eyebrow plain">Confirmed by 2+ scanners</span>
              <p className="numeral">{fmt(confirmed)}</p>
              <p className="small muted">findings that independent scanners each reported, and that Bulwark merged into one.</p>
            </div>
          </div>
        </section>
      </StackSection>

      {/* ---- Plug it in ---- */}
      <StackSection index={7}>
        <section className="section" id="plug-in" aria-labelledby="plug-h">
          <div className="sec-head">
            <div className="stack">
              <span className="eyebrow">Plug it in</span>
              <h2 id="plug-h">One engine, wherever you work</h2>
            </div>
            <div className="actions"><a href={DOCS_HREF} className="btn sm">API reference</a></div>
          </div>
          <div className="plug-sec">
            <div className="cell"><PlugIn items={snippets()} /></div>
            <div className="cell stack">
              <span className="label">Same engine, same results</span>
              <ul className="plug-list">
                <li><b>CLI</b><span>A scan with no server at all: JSON, SARIF, HTML or a signed PDF.</span></li>
                <li><b>GitHub Action</b><span>Gates pull requests on what they introduce, not on old debt.</span></li>
                <li><b>MCP</b><span>Your own agent reads Issues and fixes as you; it cannot change anything.</span></li>
                <li><b>REST API</b><span>Everything the web app does, with scoped tokens and a WebSocket for live progress.</span></li>
              </ul>
            </div>
          </div>
        </section>
      </StackSection>

      {/* ---- Scanners + one finding's path ---- */}
      <StackSection index={8}>
        <section className="section ingredients" id="scanners" aria-labelledby="scan-h">
          <div className="cell stack">
            <span className="eyebrow">The default scanners [05]</span>
            <h2 id="scan-h">Best-in-class open source, one pipeline</h2>
            <p className="lede">Detection is delegated to mature tools. Bulwark&apos;s contribution is normalisation, correlation and prioritisation. <Link href="/integrations">All {catalogue.scanners} scanners and {catalogue.parsers} import formats →</Link></p>
            <Scanners />
          </div>
          <div className="hero-art">
            <Glow className="solution">
              <div className="panel-head"><span className="eyebrow plain">Follow one finding</span><span className="label">6 steps</span></div>
              <div className="grid-bg path-teaser">
                <ol>
                  <li><span>01</span>Bandit and Semgrep report one SQL injection</li>
                  <li><span>02</span>Both become one shape: CWE-89, HIGH</li>
                  <li><span>03</span>Merged into one finding, with a fingerprint</li>
                  <li><span>04</span>Ranked by risk, not by count</li>
                  <li><span>05</span>Tracked as an Issue, with an SLA and a ticket</li>
                  <li><span>06</span>Fixed, and checked by a targeted retest</li>
                </ol>
              </div>
              <div className="panel-foot"><Link href="/how-it-works#story">See every step →</Link><span>A real scan</span></div>
            </Glow>
          </div>
        </section>
      </StackSection>

      {/* ---- Shipped / roadmap ---- */}
      <StackSection index={9}>
        <section className="section stackrow" aria-label="Status">
          <div className="cell stack">
            <span className="eyebrow">What ships today</span>
            <h2>Built like a security tool</h2>
            <ul className="checklist">
              <li>Sandboxed scanners and report parsers</li>
              <li>Cross-tool correlation, per-source deduplication</li>
              <li>REST + WebSocket API, CLI, VS Code extension and GitHub Action</li>
              <li>EPSS + CISA KEV risk score, with reachability analysis</li>
              <li>SLAs, four-eyes risk acceptance, tickets both ways</li>
              <li>Single sign-on (OIDC, SAML), SCIM and scoped roles</li>
              <li>Signed reports, SBOMs, VEX and attestations</li>
              <li>Strict CSP, text-only rendering of scanner data</li>
              <li>An MCP server for your own agent, read-only by default</li>
              <li>/fix on pull requests: previewed, capped, never for forks</li>
            </ul>
          </div>
          <div className="cell stack">
            <span className="eyebrow plain">Roadmap</span>
            <h2>Next: launch</h2>
            <ul className="checklist">
              <li className="soon">Editor and CI marketplace listings (install from source today)</li>
              <li className="soon">The verified-fix agent measured against a real model</li>
            </ul>
          </div>
        </section>
      </StackSection>

      {/* ---- CTA + footer (the last panel slides over everything) ---- */}
      <StackSection index={10}>
      <section className="cta" aria-label="Get started">
        <Stripes seed={7} groups={16} rows={2} />
        <div className="cta-copy">
          <span className="eyebrow">Get started</span>
          <h2 className="display">Scan your first repo in a minute.</h2>
          <div className="hero-actions"><Link href={APP_HREF} className="btn primary">{APP_CTA}</Link></div>
          <span className="tagline">[ Bulwark ] local-first / sandboxed_</span>
        </div>
      </section>
      <SiteFooter />
      </StackSection>
    </div>
  );
}
