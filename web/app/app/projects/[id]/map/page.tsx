import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { MapperScreen } from "@/components/MapperScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Map a format · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell
        crumbs={[
          { label: "Projects", href: "/app/projects" },
          { label: "Project", href: `/app/projects/${id}` },
          { label: "Import", href: `/app/projects/${id}/import` },
          { label: "Map a format" },
        ]}
      >
        <MapperScreen assetId={id} />
      </AppShell>
    </TokenGate>
  );
}
