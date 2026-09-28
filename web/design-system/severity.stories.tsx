import type { Meta, StoryObj } from "@storybook/react-vite";
import { SeverityBadge, SeverityIcon, SEVERITIES } from "./severity";

const meta: Meta = {
  title: "Design system/Severity",
};
export default meta;

export const AllLevels: StoryObj = {
  render: () => (
    <div style={{ display: "grid", gap: "0.75rem" }}>
      {SEVERITIES.map((s) => (
        <SeverityBadge key={s} severity={s} />
      ))}
    </div>
  ),
};

export const CriticalReachability: StoryObj = {
  name: "Critical: reachable vs. not reachable (calm by default, §29.2)",
  render: () => (
    <div style={{ display: "grid", gap: "0.75rem" }}>
      <SeverityBadge severity="critical" reachable />
      <SeverityBadge severity="critical" reachable={false} />
    </div>
  ),
};

export const IconsOnly: StoryObj = {
  render: () => (
    <div style={{ display: "flex", gap: "1rem" }}>
      {SEVERITIES.map((s) => (
        <SeverityIcon key={s} severity={s} size={24} />
      ))}
    </div>
  ),
};
