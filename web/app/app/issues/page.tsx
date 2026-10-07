import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { IssuesScreen } from "@/components/issues/IssuesScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Issues · Bulwark" };

const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v) ?? "";

export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const raw = await searchParams;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Issues" }]} eyebrow="Every project" title="Issues">
        <IssuesScreen initialQuery={one(raw.q)} initialSort={one(raw.sort)} initialView={one(raw.view)} />
      </AppShell>
    </TokenGate>
  );
}
