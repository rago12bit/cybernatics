import type { Meta, StoryObj } from "@storybook/react-vite";
import { Dialog } from "./Dialog";
import { Button } from "./Button";

const meta: Meta = {
  title: "Design system/Dialog",
};
export default meta;

export const Default: StoryObj = {
  render: () => (
    <Dialog trigger={<Button variant="primary">Accept risk</Button>} title="Accept this risk" description="Choose an expiry date. The finding reappears automatically once it passes.">
      <Button variant="primary">Confirm</Button>
    </Dialog>
  ),
};
