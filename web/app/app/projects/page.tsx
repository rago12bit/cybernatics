import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { ProjectsList } from "@/components/ProjectsList";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Projects · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Projects" }]}>
        <ProjectsList />
      </AppShell>
    </TokenGate>
  );
}
