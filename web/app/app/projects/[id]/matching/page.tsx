import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { MatchingScreen } from "@/components/MatchingScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Matching · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell
        crumbs={[
          { label: "Projects", href: "/app/projects" },
          { label: "Project", href: `/app/projects/${id}` },
          { label: "Matching" },
        ]}
      >
        <MatchingScreen assetId={id} />
      </AppShell>
    </TokenGate>
  );
}
