import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { WebAssetVerification } from "@/components/WebAssetVerification";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Add a web target · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Projects", href: "/app/projects" }, { label: "Add web target" }]}>
        <WebAssetVerification />
      </AppShell>
    </TokenGate>
  );
}
