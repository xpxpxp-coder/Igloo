import { SnowmanPulseMark } from "@/shared/ui/snowman-logo/SnowmanPulseMark";

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
  return <SnowmanPulseMark className={className} pulse={pulse} />;
}
