import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { ManualFindingForm } from "@/components/ManualFindingForm";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Record a finding · Bulwark" };

export default async function Page({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ engagement?: string | string[] }>;
}) {
  const { id } = await params;
  const { engagement } = await searchParams;
  return (
    <TokenGate>
      <AppShell
        crumbs={[
          { label: "Projects", href: "/app/projects" },
          { label: "Project", href: `/app/projects/${id}` },
          { label: "Record a finding" },
        ]}
      >
        <ManualFindingForm assetId={id} engagementId={typeof engagement === "string" ? engagement : undefined} />
      </AppShell>
    </TokenGate>
  );
}
