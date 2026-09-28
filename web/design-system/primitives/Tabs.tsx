import * as RadixTabs from "@radix-ui/react-tabs";
import type { ReactElement, ReactNode } from "react";
import "../primitives.css";

export function Tabs({
  tabs,
  defaultValue,
}: {
  tabs: { value: string; label: string; content: ReactNode }[];
  defaultValue?: string;
}): ReactElement {
  return (
    <RadixTabs.Root defaultValue={defaultValue ?? tabs[0]?.value} className="ds-tabs-root">
      <RadixTabs.List className="ds-tabs-list">
        {tabs.map((t) => (
          <RadixTabs.Trigger key={t.value} value={t.value} className="ds-tabs-trigger">
            {t.label}
          </RadixTabs.Trigger>
        ))}
      </RadixTabs.List>
      {tabs.map((t) => (
        <RadixTabs.Content key={t.value} value={t.value} className="ds-tabs-content">
          {t.content}
        </RadixTabs.Content>
      ))}
    </RadixTabs.Root>
  );
}
