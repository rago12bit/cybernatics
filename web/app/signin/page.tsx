import type { Metadata } from "next";
import { SignInPage } from "@/components/SignInPage";

export const metadata: Metadata = { title: "Sign in · Bulwark" };

const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v) ?? null;

/* Where the API sends a sign-in that did not work (`?error=`), and where anyone can start one. */
export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const raw = await searchParams;
  return <SignInPage error={one(raw.error)} next={one(raw.next) ?? "/app"} />;
}
