import type { Metadata } from "next";
import { Landing } from "@/components/site/Landing";

export const metadata: Metadata = {
  title: "About · Bulwark",
  description: "Five open-source scanners, one deduplicated list of findings.",
};

export default function About() {
  return <Landing />;
}
