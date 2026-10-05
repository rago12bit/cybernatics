import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { ChecklistScreen } from "@/components/ChecklistScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Checklist · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell
        crumbs={[
          { label: "Projects", href: "/app/projects" },
          { label: "Engagement", href: `/app/engagements/${id}` },
          { label: "Checklist" },
        ]}
      >
        <ChecklistScreen id={id} />
      </AppShell>
    </TokenGate>
  );
}
