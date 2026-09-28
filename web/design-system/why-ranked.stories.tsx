import type { Meta, StoryObj } from "@storybook/react-vite";
import { WhyRankedPanel, WhyRankedTrigger } from "./why-ranked";
import { Button } from "./primitives/Button";

const meta: Meta = {
  title: "Design system/Why it's ranked (C8)",
};
export default meta;

const FACTORS = ["Reachable from POST /login", "In CISA KEV: exploited in the wild", "Flagged by 2 scanners, confidence 90%"];

export const Panel: StoryObj = {
  render: () => <WhyRankedPanel factors={FACTORS} riskScore={92} />,
};

export const PanelWithoutAScore: StoryObj = {
  render: () => <WhyRankedPanel factors={["No CVE id to look up exploit data", "High severity"]} />,
};

export const PanelWithNoFactorsRendersNothing: StoryObj = {
  render: () => <WhyRankedPanel factors={[]} />,
};

export const CompactTrigger: StoryObj = {
  name: "Compact trigger (list rows)",
  render: () => (
    <WhyRankedTrigger factors={FACTORS}>
      <Button>Rank #1</Button>
    </WhyRankedTrigger>
  ),
};
