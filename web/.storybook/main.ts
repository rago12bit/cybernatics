import type { StorybookConfig } from "@storybook/react-vite";

const config: StorybookConfig = {
  stories: ["../design-system/**/*.stories.tsx"],
  addons: [],
  framework: {
    name: "@storybook/react-vite",
    options: {},
  },
  // These primitives are plain React + CSS custom properties (no Next.js APIs), so the light
  // react-vite framework is enough — no need for @storybook/nextjs here.
  staticDirs: [],
};

export default config;
