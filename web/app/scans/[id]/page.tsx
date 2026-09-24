import { ScanPage } from "@/components/ScanPage";
import { TokenGate } from "@/components/TokenGate";

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <div className="page">
      <TokenGate>
        <ScanPage id={id} />
      </TokenGate>
    </div>
  );
}
