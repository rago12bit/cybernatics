import * as RadixDialog from "@radix-ui/react-dialog";
import type { ReactElement, ReactNode } from "react";
import "../primitives.css";

export function Dialog({
  trigger,
  title,
  description,
  children,
  open,
  onOpenChange,
}: {
  trigger?: ReactElement;
  title: string;
  description?: string;
  children?: ReactNode;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}): ReactElement {
  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      {trigger && <RadixDialog.Trigger asChild>{trigger}</RadixDialog.Trigger>}
      <RadixDialog.Portal>
        <RadixDialog.Overlay className="ds-dialog-overlay" />
        <RadixDialog.Content className="ds-dialog-content">
          <RadixDialog.Title className="ds-dialog-title">{title}</RadixDialog.Title>
          {description && <RadixDialog.Description className="ds-dialog-description">{description}</RadixDialog.Description>}
          {children}
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
}
