import type { VexJustification } from "@/lib/types";

/** OpenVEX's justifications (plan §46.3), with the plain sentence the screens show. */
export const JUSTIFICATIONS: { value: VexJustification; label: string }[] = [
  { value: "component_not_present", label: "The vulnerable component is not in the product" },
  { value: "vulnerable_code_not_present", label: "The component is there, but not its vulnerable code" },
  { value: "vulnerable_code_not_in_execute_path", label: "The vulnerable code is never executed" },
  { value: "vulnerable_code_cannot_be_controlled_by_adversary", label: "An attacker cannot control the vulnerable code's input" },
  { value: "inline_mitigations_already_exist", label: "Built-in protections already stop it" },
];

export const justificationLabel = (v: string | null | undefined) =>
  JUSTIFICATIONS.find((j) => j.value === v)?.label ?? null;
