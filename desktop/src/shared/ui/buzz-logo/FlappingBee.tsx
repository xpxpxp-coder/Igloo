import { SnowmanPulseMark } from "@/shared/ui/snowman-logo/SnowmanPulseMark";

/**
 * Animated Snowman product mark. The legacy export name is preserved only to
 * avoid a flag-day internal API rename across compatibility surfaces.
 */
export function FlappingBee({ className }: { className?: string }) {
  return <SnowmanPulseMark className={className} />;
}
