import type { Meta, StoryObj } from "@storybook/react-vite";
import { DropdownMenu } from "./DropdownMenu";
import { Button } from "./Button";

const meta: Meta = {
  title: "Design system/Dropdown menu",
};
export default meta;

export const Default: StoryObj = {
  render: () => (
    <DropdownMenu
      trigger={<Button>Project ▾</Button>}
      items={[
        { label: "acme/payments-api" },
        { label: "acme/checkout-service" },
        "separator",
        { label: "Add a project" },
      ]}
    />
  ),
};

export const WithDisabledItem: StoryObj = {
  render: () => (
    <DropdownMenu
      trigger={<Button>Actions ▾</Button>}
      items={[{ label: "Review fix" }, { label: "Accept risk", disabled: true }]}
    />
  ),
};
