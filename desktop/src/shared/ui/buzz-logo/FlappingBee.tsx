import { BuzzMark } from "./BuzzMark";

/**
 * Animated Snowman product mark. The legacy export name is preserved only to
 * avoid a flag-day internal API rename across compatibility surfaces.
 */
export function FlappingBee({ className }: { className?: string }) {
  return (
    <BuzzMark
      className={["animate-pulse motion-reduce:animate-none", className]
        .filter(Boolean)
        .join(" ")}
    />
  );
}
