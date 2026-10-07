import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { ScanComparison } from "@/components/ScanComparison";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Compare scans · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell
        crumbs={[
          { label: "Projects", href: "/app/projects" },
          { label: "Overview", href: `/app/projects/${id}` },
          { label: "Compare scans" },
        ]}
        eyebrow="Project"
        title="Compare scans"
      >
        <ScanComparison assetId={id} />
      </AppShell>
    </TokenGate>
  );
}
