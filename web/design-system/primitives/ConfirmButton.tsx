import { useState, type ButtonHTMLAttributes, type ReactElement } from "react";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import "../primitives.css";

type ConfirmButtonProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, "onClick" | "title"> & {
  /** The question, e.g. "Revoke the token CI?" */
  title: string;
  /** What happens if they go ahead, in a sentence. */
  description?: string;
  /** The verb on the button that does it, e.g. "Revoke". */
  confirmLabel: string;
  cancelLabel?: string;
  onConfirm: () => unknown;
};

/**
 * A button for something that can't be undone. The first click only asks; the action runs from the
 * dialog's own button, so one misclick never revokes, removes or deletes anything.
 */
export function ConfirmButton({
  title, description, confirmLabel, cancelLabel = "Cancel", onConfirm, type = "button", ...rest
}: ConfirmButtonProps): ReactElement {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen} trigger={<button type={type} {...rest} />} title={title} description={description}>
      <div className="ds-dialog-actions">
        <Button type="button" variant="primary" onClick={() => { setOpen(false); void onConfirm(); }}>{confirmLabel}</Button>
        <Button type="button" onClick={() => setOpen(false)}>{cancelLabel}</Button>
      </div>
    </Dialog>
  );
}
