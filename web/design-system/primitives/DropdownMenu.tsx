import * as RadixDropdown from "@radix-ui/react-dropdown-menu";
import type { ReactElement, ReactNode } from "react";
import "../primitives.css";

export type DropdownItem = { label: string; onSelect?: () => void; disabled?: boolean } | "separator";

export function DropdownMenu({ trigger, items }: { trigger: ReactElement; items: DropdownItem[] }): ReactElement {
  return (
    <RadixDropdown.Root>
      <RadixDropdown.Trigger asChild>{trigger}</RadixDropdown.Trigger>
      <RadixDropdown.Portal>
        <RadixDropdown.Content className="ds-dropdown-content" sideOffset={6} align="start">
          {items.map((item, i) =>
            item === "separator" ? (
              <RadixDropdown.Separator key={i} className="ds-dropdown-separator" />
            ) : (
              <RadixDropdown.Item key={item.label} className="ds-dropdown-item" disabled={item.disabled} onSelect={item.onSelect}>
                {item.label}
              </RadixDropdown.Item>
            ),
          )}
        </RadixDropdown.Content>
      </RadixDropdown.Portal>
    </RadixDropdown.Root>
  );
}

export function DropdownMenuChildren({ trigger, children }: { trigger: ReactElement; children: ReactNode }): ReactElement {
  return (
    <RadixDropdown.Root>
      <RadixDropdown.Trigger asChild>{trigger}</RadixDropdown.Trigger>
      <RadixDropdown.Portal>
        <RadixDropdown.Content className="ds-dropdown-content" sideOffset={6} align="start">
          {children}
        </RadixDropdown.Content>
      </RadixDropdown.Portal>
    </RadixDropdown.Root>
  );
}
