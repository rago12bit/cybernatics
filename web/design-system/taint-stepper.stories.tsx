import type { Meta, StoryObj } from "@storybook/react-vite";
import { useState } from "react";
import { TaintStepper } from "./taint-stepper";

const meta: Meta = {
  title: "Design system/Taint stepper",
};
export default meta;

export const SingleRealStep: StoryObj = {
  name: "Single real step (today's data)",
  render: () => {
    function Demo() {
      const [active, setActive] = useState(0);
      return <TaintStepper steps={[{ path: "db/queries.py", line: 12, label: "Where this happens" }]} activeIndex={active} onStepClick={setActive} />;
    }
    return <Demo />;
  },
};

export const MultiStepExample: StoryObj = {
  name: "Multi-step (illustrative — Phase 9 supplies real paths)",
  render: () => {
    function Demo() {
      const [active, setActive] = useState(2);
      const steps = [
        { path: "routes/auth.py", line: 21, label: "username from form" },
        { path: "services/user.py", line: 40, label: "find_user(username)" },
        { path: "db/queries.py", line: 12, label: "cursor.execute(q)" },
      ];
      return <TaintStepper steps={steps} activeIndex={active} onStepClick={setActive} />;
    }
    return <Demo />;
  },
};
