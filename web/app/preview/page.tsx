import { notFound } from "next/navigation";
import { PreviewClient } from "./PreviewClient";

// Development-only: renders the real UI with sample data so the design can be reviewed without an
// API token. It does not exist in production builds.
export default function Page() {
  if (process.env.NODE_ENV !== "development") notFound();
  return <PreviewClient />;
}
