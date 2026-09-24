"use client";

import Link from "next/link";
import { useEffect } from "react";

export default function ErrorPage({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => { console.error(error); }, [error]);
  return (
    <div className="page">
      <div className="state-page" role="alert">
        <span className="eyebrow plain">Something went wrong</span>
        <h1>This page hit an unexpected error.</h1>
        <p className="lede">Nothing was lost: your scans are stored on the server. Try again, or head back.</p>
        <div className="hero-actions">
          <button type="button" className="btn primary" onClick={reset}>Try again</button>
          <Link href="/" className="btn">Back home</Link>
        </div>
      </div>
    </div>
  );
}
