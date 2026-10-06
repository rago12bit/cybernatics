import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { RuleEditor } from "@/components/RuleEditor";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Rule · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Automation", href: "/app/automation" }, { label: "Rule" }]}>
        <RuleEditor ruleId={id} />
      </AppShell>
    </TokenGate>
  );
}
