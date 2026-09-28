import type { Meta, StoryObj } from "@storybook/react-vite";
import { Button } from "./Button";

const meta: Meta<typeof Button> = {
  title: "Design system/Button",
  component: Button,
};
export default meta;

export const Default: StoryObj<typeof Button> = {
  args: { children: "Review fix" },
};

export const Primary: StoryObj<typeof Button> = {
  args: { children: "Review fix", variant: "primary" },
};

export const Disabled: StoryObj<typeof Button> = {
  args: { children: "Rotate the key", disabled: true },
};

export const AllVariants: StoryObj = {
  render: () => (
    <div style={{ display: "flex", gap: "0.75rem" }}>
      <Button>Default</Button>
      <Button variant="primary">Primary</Button>
      <Button disabled>Disabled</Button>
    </div>
  ),
};
