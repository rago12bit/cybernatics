import type { Metadata } from "next";
import { LiveJuiceShopDemo } from "@/components/LiveJuiceShopDemo";

export const metadata: Metadata = {
  title: "Recorded scan · Bulwark",
  description: "A real scan of one release of OWASP Juice Shop, its code and its running app, so you can explore the report without running anything.",
};

// A real scan of the public OWASP Juice Shop replaying as it would live (plan §33, Week 52).
export default function Sample() {
  return <LiveJuiceShopDemo />;
}
