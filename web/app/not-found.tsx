import Link from "next/link";

export default function NotFound() {
  return (
    <div className="page">
      <div className="state-page">
        <span className="eyebrow">404</span>
        <h1>That page does not exist.</h1>
        <p className="lede">The link may be old, or the scan may have been removed.</p>
        <div className="hero-actions">
          <Link href="/" className="btn primary">Back home →</Link>
          <Link href="/sample" className="btn">View a sample scan</Link>
        </div>
      </div>
    </div>
  );
}
