import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { HypothesesLane } from "@/components/HypothesesLane";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Hypotheses · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Projects", href: "/app/projects" }, { label: "Hypotheses" }]}>
        <HypothesesLane assetId={id} />
      </AppShell>
    </TokenGate>
  );
}
