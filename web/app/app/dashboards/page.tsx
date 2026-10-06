import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { DashboardScreen } from "@/components/dashboard/DashboardScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Dashboards · Bulwark" };

export default async function Page({ searchParams }: { searchParams: Promise<{ d?: string | string[] }> }) {
  const { d } = await searchParams;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Dashboards" }]}>
        <DashboardScreen initialId={typeof d === "string" ? d : undefined} />
      </AppShell>
    </TokenGate>
  );
}
