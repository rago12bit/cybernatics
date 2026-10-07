import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { UnitList } from "@/components/home/UnitOverviewScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Business units · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Business units" }]}>
        <div className="dash">
          <UnitList />
        </div>
      </AppShell>
    </TokenGate>
  );
}
