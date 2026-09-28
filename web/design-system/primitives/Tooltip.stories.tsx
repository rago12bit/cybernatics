import type { Meta, StoryObj } from "@storybook/react-vite";
import { Tooltip } from "./Tooltip";
import { Button } from "./Button";

const meta: Meta = {
  title: "Design system/Tooltip",
};
export default meta;

export const Default: StoryObj = {
  render: () => (
    <Tooltip label="Reachable from POST /login">
      <Button>Hover me</Button>
    </Tooltip>
  ),
};
