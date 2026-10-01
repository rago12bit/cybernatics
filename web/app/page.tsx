import { LiveJuiceShopDemo } from "@/components/LiveJuiceShopDemo";

// The first thing anyone sees is a real scan happening, not a block of statistics (plan §33, Week
// 52's launch page); the pitch lives at /about, a smaller fixed sample at /sample, and scanning
// your own code at /app.
export default function Home() {
  return <LiveJuiceShopDemo />;
}
