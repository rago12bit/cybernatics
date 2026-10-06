import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { ProjectVexScreen } from "@/components/ProjectVexScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "VEX · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell
        crumbs={[
          { label: "Projects", href: "/app/projects" },
          { label: "Project", href: `/app/projects/${id}` },
          { label: "VEX" },
        ]}
      >
        <ProjectVexScreen assetId={id} />
      </AppShell>
    </TokenGate>
  );
}
