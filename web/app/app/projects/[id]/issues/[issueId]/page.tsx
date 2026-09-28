import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { IssueDetail } from "@/components/IssueDetail";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Issue · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string; issueId: string }> }) {
  const { id, issueId } = await params;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Projects", href: "/app/projects" }, { label: "Issues", href: `/app/projects/${id}/issues` }]}>
        <IssueDetail assetId={id} issueId={issueId} />
      </AppShell>
    </TokenGate>
  );
}
