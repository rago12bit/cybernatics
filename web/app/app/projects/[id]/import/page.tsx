import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { ImportScreen } from "@/components/ImportScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Import a report · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell
        crumbs={[
          { label: "Projects", href: "/app/projects" },
          { label: "Project", href: `/app/projects/${id}` },
          { label: "Import" },
        ]}
      >
        <ImportScreen assetId={id} />
      </AppShell>
    </TokenGate>
  );
}
