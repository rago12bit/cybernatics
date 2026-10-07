import type { Metadata } from "next";
import Link from "next/link";
import { IntegrationsCatalogue } from "@/components/site/IntegrationsCatalogue";
import { SitePage } from "@/components/site/SitePage";
import { counts } from "@/lib/catalogue";

export const metadata: Metadata = {
  title: "Integrations · Bulwark",
  description: "Every scanner, report format, connector, ticket system and notification channel Bulwark supports, generated from its code.",
};

export default function Integrations() {
  const c = counts();
  return (
    <SitePage
      eyebrow="Integrations"
      title="What Bulwark works with"
      lede={
        <>
          {c.scanners} scanners it runs itself, {c.parsers} report formats it imports (and any other JSON, CSV or XML
          report through a saved mapping), and {c.connectors} connectors. This list is generated from the code&apos;s own
          registries, so it cannot list something Bulwark does not do.
        </>
      }
      actions={<Link href="/migrate" className="btn sm">Coming from DefectDojo? →</Link>}
    >
      <IntegrationsCatalogue />
    </SitePage>
  );
}
