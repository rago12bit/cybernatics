import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { UnitOverviewScreen } from "@/components/home/UnitOverviewScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Business unit · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Business units", href: "/app/portfolios" }, { label: "Overview" }]}>
        <UnitOverviewScreen id={id} />
      </AppShell>
    </TokenGate>
  );
}
