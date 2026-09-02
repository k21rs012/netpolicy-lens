import { Check, CircleHelp, WifiOff, X, Zap } from "lucide-react";

import type { Result } from "../types";


const resultLabel: Record<Result, string> = {
  ALLOW: "許可",
  DENY: "拒否",
  PARTIAL: "一部許可",
  UNKNOWN: "不明",
  SAME_SEGMENT: "同一",
  NO_ROUTE: "経路なし",
};


export function Status({
  value,
  compact = false,
}: {
  value: Result;
  compact?: boolean;
}) {
  return (
    <span className={`status ${value.toLowerCase()} ${compact ? "compact" : ""}`}>
      {value === "ALLOW" ? (
        <Check />
      ) : value === "DENY" ? (
        <X />
      ) : value === "PARTIAL" ? (
        <Zap />
      ) : value === "UNKNOWN" ? (
        <CircleHelp />
      ) : value === "NO_ROUTE" ? (
        <WifiOff />
      ) : (
        <span>—</span>
      )}
      {!compact && resultLabel[value]}
    </span>
  );
}
