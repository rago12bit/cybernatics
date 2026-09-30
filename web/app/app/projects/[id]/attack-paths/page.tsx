import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { AttackPathsScreen } from "@/components/AttackPathsScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Attack paths · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Projects", href: "/app/projects" }, { label: "Attack paths" }]}>
        <AttackPathsScreen assetId={id} />
      </AppShell>
    </TokenGate>
  );
}
