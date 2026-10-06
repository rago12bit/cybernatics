import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { ComponentsScreen } from "@/components/ComponentsScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Components · Bulwark" };

const one = (v: string | string[] | undefined) => (typeof v === "string" ? v : "");

export default async function Page({
  searchParams,
}: {
  searchParams: Promise<{ purl?: string | string[]; version?: string | string[] }>;
}) {
  const { purl, version } = await searchParams;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Components" }]}>
        <ComponentsScreen initialPurl={one(purl)} initialVersion={one(version)} />
      </AppShell>
    </TokenGate>
  );
}
