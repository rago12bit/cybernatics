import { DemoReport } from "@/components/DemoReport";

// The smaller, fixed sample report that used to live at "/" before Week 52 made the live Juice
// Shop replay the homepage -- kept at its own route rather than removed.
export default function Sample() {
  return <DemoReport />;
}
