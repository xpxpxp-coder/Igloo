import { cn } from "@/shared/lib/cn";
import { BuzzMark } from "./BuzzMark";

export type FuzzyLogoProps = {
  fuzz?: boolean;
  className?: string;
  ariaLabel?: string;
  loop?: boolean;
  loopRestSeconds?: number;
  pulse?: boolean;
  reverse?: boolean;
  variant?: "v1" | "v2" | "v3" | "v4" | "v5" | "v6" | "v7" | "v8";
};

/** Animated Snowman mark with the legacy prop surface retained for callers. */
export function FuzzyLogo({ className, pulse = true }: FuzzyLogoProps) {
  return (
    <BuzzMark
      className={cn(pulse && "animate-pulse motion-reduce:animate-none", className)}
    />
  );
}
