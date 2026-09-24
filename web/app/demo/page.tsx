import type { Metadata } from "next";
import { DemoReport } from "@/components/DemoReport";

export const metadata: Metadata = {
  title: "Sample scan · Bulwark",
  description: "Explore a real Bulwark report: five scanners, merged findings, no sign-in needed.",
};

export default function DemoPage() {
  return <DemoReport />;
}
