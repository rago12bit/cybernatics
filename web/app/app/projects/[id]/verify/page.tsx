import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { WebAssetVerification } from "@/components/WebAssetVerification";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Ownership verification · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Projects", href: "/app/projects" }, { label: "Verification" }]}>
        <WebAssetVerification assetId={id} />
      </AppShell>
    </TokenGate>
  );
}
