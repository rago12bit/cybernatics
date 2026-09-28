import type { Meta, StoryObj } from "@storybook/react-vite";
import { Tabs } from "./Tabs";

const meta: Meta = {
  title: "Design system/Tabs",
};
export default meta;

export const Default: StoryObj = {
  render: () => (
    <Tabs
      tabs={[
        { value: "overview", label: "Overview", content: <p>Project overview content.</p> },
        { value: "issues", label: "Issues", content: <p>Issues table content.</p> },
        { value: "history", label: "History", content: <p>Scan history content.</p> },
      ]}
    />
  ),
};
