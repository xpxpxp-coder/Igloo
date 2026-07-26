import { cn } from "@/shared/lib/cn";
import { SnowmanMark } from "./SnowmanMark";

export type SnowmanPulseMarkProps = {
  className?: string;
  ariaLabel?: string;
  pulse?: boolean;
};

/** Subtle activity treatment that is disabled for reduced-motion users. */
export function SnowmanPulseMark({
  className,
  pulse = true,
}: SnowmanPulseMarkProps) {
  return (
    <SnowmanMark
      className={cn(
        pulse && "animate-pulse motion-reduce:animate-none",
        className,
      )}
    />
  );
}
