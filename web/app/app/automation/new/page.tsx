import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { RuleEditor } from "@/components/RuleEditor";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "New rule · Bulwark" };

export default async function Page({ searchParams }: { searchParams: Promise<{ template?: string }> }) {
  const { template } = await searchParams;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Automation", href: "/app/automation" }, { label: "New rule" }]}>
        <RuleEditor templateKey={template} />
      </AppShell>
    </TokenGate>
  );
}
