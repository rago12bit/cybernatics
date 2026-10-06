import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { MetricIssuesScreen } from "@/components/dashboard/MetricIssuesScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Issues behind a number · Bulwark" };

export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const raw = await searchParams;
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(raw)) for (const one of Array.isArray(v) ? v : v ? [v] : []) q.append(k, one);
  const query = q.toString();
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Dashboards", href: "/app/dashboards" }, { label: "Issues" }]}>
        <MetricIssuesScreen key={query} query={query} />
      </AppShell>
    </TokenGate>
  );
}
