"use client";

import { useRouter } from "next/navigation";
import { SignIn } from "./SignIn";

export function SignInPage({ error, next }: { error: string | null; next: string }) {
  const router = useRouter();
  const safe = next.startsWith("/") && !next.startsWith("//") ? next : "/app";
  return <SignIn error={error} next={safe} onToken={() => router.push(safe)} />;
}
