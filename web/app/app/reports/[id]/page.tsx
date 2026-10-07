import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { ReportBuilder } from "@/components/reports/ReportBuilder";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Report · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Reports", href: "/app/reports" }, { label: "Report" }]}>
        <ReportBuilder reportId={id} />
      </AppShell>
    </TokenGate>
  );
}
