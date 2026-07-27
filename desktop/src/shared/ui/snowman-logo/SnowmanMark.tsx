/** Canonical Snowman Command Center product mark. */
export function SnowmanMark({ className }: { className?: string }) {
  return (
    <svg
      aria-label="Snowman Command Center"
      className={["snowman-mark", className].filter(Boolean).join(" ")}
      role="img"
      viewBox="0 0 128 128"
    >
      <circle cx="64" cy="64" r="62" fill="#10233f" />
      <circle cx="64" cy="80" r="30" fill="#f7fbff" />
      <circle cx="64" cy="43" r="22" fill="#fff" />
      <circle cx="56" cy="39" r="3" fill="#10233f" />
      <circle cx="72" cy="39" r="3" fill="#10233f" />
      <path d="M64 44l15 5-15 4z" fill="#ff9f43" />
      <path
        d="M51 54c8 6 18 6 26 0"
        fill="none"
        stroke="#10233f"
        strokeLinecap="round"
        strokeWidth="3"
      />
      <circle cx="64" cy="70" r="3" fill="#10233f" />
      <circle cx="64" cy="82" r="3" fill="#10233f" />
      <circle cx="64" cy="94" r="3" fill="#10233f" />
      <path d="M42 29h44l-6-12H48z" fill="#55c2ff" />
      <path
        d="M38 29h52"
        stroke="#55c2ff"
        strokeLinecap="round"
        strokeWidth="6"
      />
    </svg>
  );
}
