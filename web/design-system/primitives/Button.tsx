import type { ButtonHTMLAttributes, ReactElement } from "react";
import "../primitives.css";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "primary";
};

export function Button({ variant = "default", className, ...rest }: ButtonProps): ReactElement {
  const cls = ["ds-button", variant === "primary" ? "primary" : "", className].filter(Boolean).join(" ");
  return <button className={cls} {...rest} />;
}
