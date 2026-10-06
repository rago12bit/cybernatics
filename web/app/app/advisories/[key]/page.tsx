import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { AdvisoryScreen } from "@/components/AdvisoryScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Advisory · Bulwark" };

export default async function Page({ params }: { params: Promise<{ key: string }> }) {
  const { key } = await params;
  const vulnKey = decodeURIComponent(key);
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Advisories", href: "/app/advisories" }, { label: vulnKey }]}>
        <AdvisoryScreen vulnKey={vulnKey} />
      </AppShell>
    </TokenGate>
  );
}
