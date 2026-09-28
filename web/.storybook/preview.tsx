import type { Preview } from "@storybook/react-vite";
import React, { useEffect } from "react";
import "../design-system/fonts.css";
import "../design-system/tokens.css";
import { TooltipProvider } from "../design-system/primitives/Tooltip";

// tokens.css keys its dark palette off `:root[data-theme="dark"]` (matching how the real app will
// set it later), so the toggle below has to land on document.documentElement — a wrapper div's own
// data-theme attribute doesn't affect :root and the browser's prefers-color-scheme would silently
// win instead. Caught by actually toggling the control in a live Storybook run, not by inspection.
function useDocumentTheme(theme: string): void {
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    return () => document.documentElement.removeAttribute("data-theme");
  }, [theme]);
}

const preview: Preview = {
  parameters: {
    controls: { matchers: { color: /(background|color)$/i, date: /Date$/i } },
  },
  globalTypes: {
    theme: {
      description: "Light or dark (plan §29.2)",
      toolbar: {
        icon: "circlehollow",
        items: [
          { value: "light", title: "Light" },
          { value: "dark", title: "Dark" },
        ],
        dynamicTitle: true,
      },
    },
  },
  initialGlobals: { theme: "light" },
  decorators: [
    (Story, context) => {
      const theme = context.globals.theme ?? "light";
      useDocumentTheme(theme);
      return (
        <div
          style={{
            background: "var(--surface)",
            color: "var(--ink)",
            minHeight: "100vh",
            padding: "2rem",
            fontFamily: "var(--font-sans)",
          }}
        >
          <TooltipProvider>
            <Story />
          </TooltipProvider>
        </div>
      );
    },
  ],
};

export default preview;
