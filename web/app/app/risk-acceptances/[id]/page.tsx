import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { RiskAcceptanceDetail } from "@/components/RiskAcceptanceDetail";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Risk acceptance · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Risk acceptance", href: "/app/risk-acceptances" }, { label: "One request" }]}>
        <RiskAcceptanceDetail id={id} />
      </AppShell>
    </TokenGate>
  );
}
