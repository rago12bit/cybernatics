import type { Metadata } from "next";
import type { ReactNode } from "react";
import { ScrollReveal } from "@/components/site/ScrollReveal";
import { APP_REVEAL_SELECTOR } from "@/lib/reveal";

export const metadata: Metadata = { title: "App · Bulwark" };

export default function AppLayout({ children }: { children: ReactNode }) {
  return (
    <>
      <ScrollReveal selector={APP_REVEAL_SELECTOR} />
      {children}
    </>
  );
}
