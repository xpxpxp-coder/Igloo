import * as React from "react";

import { SnowmanMark } from "@/shared/ui/snowman-logo/SnowmanMark";

type SnowParticle = {
  top: string;
  left: string;
  size: number;
  rotate: number;
  color: string;
};

const WHITE = "#FFFFFF";
const GLACIER = "#55C2FF";

// Fixed scatter so the field doesn't shimmer between renders.
const SNOW_PARTICLES: SnowParticle[] = [
  { top: "4%", left: "27%", size: 34, rotate: -12, color: WHITE },
  { top: "7%", left: "58%", size: 28, rotate: 18, color: GLACIER },
  { top: "5%", left: "88%", size: 32, rotate: -20, color: WHITE },
  { top: "13%", left: "12%", size: 36, rotate: 18, color: GLACIER },
  { top: "12%", left: "73%", size: 26, rotate: -8, color: WHITE },
  { top: "18%", left: "44%", size: 24, rotate: 25, color: GLACIER },
  { top: "22%", left: "90%", size: 34, rotate: 10, color: WHITE },
  { top: "28%", left: "5%", size: 28, rotate: -18, color: GLACIER },
  { top: "31%", left: "21%", size: 24, rotate: 8, color: GLACIER },
  { top: "35%", left: "84%", size: 32, rotate: -14, color: WHITE },
  { top: "45%", left: "13%", size: 32, rotate: 20, color: GLACIER },
  { top: "47%", left: "93%", size: 26, rotate: -6, color: GLACIER },
  { top: "55%", left: "30%", size: 26, rotate: -24, color: WHITE },
  { top: "57%", left: "70%", size: 34, rotate: 12, color: GLACIER },
  { top: "63%", left: "8%", size: 34, rotate: 16, color: WHITE },
  { top: "66%", left: "88%", size: 28, rotate: -10, color: GLACIER },
  { top: "72%", left: "48%", size: 26, rotate: 22, color: GLACIER },
  { top: "76%", left: "18%", size: 32, rotate: -16, color: WHITE },
  { top: "80%", left: "64%", size: 28, rotate: 8, color: GLACIER },
  { top: "86%", left: "34%", size: 34, rotate: -20, color: WHITE },
  { top: "88%", left: "80%", size: 32, rotate: 14, color: GLACIER },
  { top: "92%", left: "10%", size: 26, rotate: -8, color: GLACIER },
  { top: "3%", left: "42%", size: 22, rotate: 14, color: WHITE },
  { top: "9%", left: "5%", size: 24, rotate: -22, color: GLACIER },
  { top: "16%", left: "62%", size: 30, rotate: -4, color: GLACIER },
  { top: "20%", left: "30%", size: 22, rotate: 12, color: WHITE },
  { top: "26%", left: "52%", size: 26, rotate: -14, color: GLACIER },
  { top: "33%", left: "68%", size: 22, rotate: 24, color: WHITE },
  { top: "40%", left: "40%", size: 24, rotate: -10, color: GLACIER },
  { top: "42%", left: "78%", size: 28, rotate: 6, color: GLACIER },
  { top: "52%", left: "55%", size: 22, rotate: -18, color: WHITE },
  { top: "60%", left: "42%", size: 28, rotate: 10, color: GLACIER },
  { top: "68%", left: "26%", size: 24, rotate: -6, color: WHITE },
  { top: "70%", left: "76%", size: 30, rotate: 18, color: GLACIER },
  { top: "82%", left: "6%", size: 28, rotate: 22, color: WHITE },
  { top: "84%", left: "50%", size: 24, rotate: -12, color: GLACIER },
  { top: "94%", left: "60%", size: 28, rotate: 16, color: GLACIER },
  { top: "95%", left: "90%", size: 22, rotate: -24, color: WHITE },
];

const REPEL_RADIUS = 180;
const REPEL_STRENGTH = 110;
// Autonomous wander: each snow crystal drifts on its own smooth loop.
const WANDER_X = 26;
const WANDER_Y = 20;

function SnowCrystal({ className }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      fill="none"
      viewBox="0 0 32 32"
    >
      <path
        d="M16 2v28M4 9l24 14M28 9 4 23M11 5l5 4 5-4M11 27l5-4 5 4M4 15l6-2-1-6M28 17l-6 2 1 6M28 15l-6-2 1-6M4 17l6 2-1 6"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
    </svg>
  );
}

export function LandingBees() {
  const fieldRef = React.useRef<HTMLDivElement>(null);
  const particleRefs = React.useRef<(HTMLSpanElement | null)[]>([]);
  const pointer = React.useRef<{ x: number; y: number } | null>(null);
  const offsets = React.useRef(SNOW_PARTICLES.map(() => ({ x: 0, y: 0 })));

  React.useEffect(() => {
    const field = fieldRef.current;
    if (!field) return;

    let raf = 0;
    const start = performance.now();

    const tick = (now: number) => {
      const t = (now - start) / 1000;
      const rect = field.getBoundingClientRect();
      const p = pointer.current;
      particleRefs.current.forEach((el, i) => {
        if (!el) return;
        const particle = SNOW_PARTICLES[i];
        // Per-particle wander: two smooth waves phase-shifted by index.
        const phase = i * 1.7;
        const wx =
          Math.sin(t * (0.7 + (i % 5) * 0.13) + phase) * WANDER_X +
          Math.sin(t * 1.9 + phase * 2.1) * 6;
        const wy =
          Math.cos(t * (0.6 + (i % 7) * 0.11) + phase) * WANDER_Y +
          Math.cos(t * 2.3 + phase * 1.3) * 5;
        let rx = 0;
        let ry = 0;
        if (p) {
          const cx = rect.left + (rect.width * parseFloat(particle.left)) / 100;
          const cy = rect.top + (rect.height * parseFloat(particle.top)) / 100;
          const ox = cx - p.x;
          const oy = cy - p.y;
          const dist = Math.hypot(ox, oy);
          if (dist < REPEL_RADIUS && dist > 0.01) {
            const push =
              ((REPEL_RADIUS - dist) / REPEL_RADIUS) * REPEL_STRENGTH;
            rx = (ox / dist) * push;
            ry = (oy / dist) * push;
          }
        }
        // Ease toward the combined target so repulsion enters/exits smoothly.
        const target = { x: wx + rx, y: wy + ry };
        const cur = offsets.current[i];
        cur.x += (target.x - cur.x) * 0.12;
        cur.y += (target.y - cur.y) * 0.12;
        el.style.transform = `translate(${cur.x}px, ${cur.y}px) rotate(${particle.rotate}deg)`;
      });
      raf = requestAnimationFrame(tick);
    };

    const onMove = (event: MouseEvent) => {
      pointer.current = { x: event.clientX, y: event.clientY };
    };
    const onLeave = () => {
      pointer.current = null;
    };

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
    if (!reduced.matches) {
      raf = requestAnimationFrame(tick);
      window.addEventListener("mousemove", onMove);
      window.addEventListener("mouseout", onLeave);
    }
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseout", onLeave);
      if (raf) cancelAnimationFrame(raf);
    };
  }, []);

  return (
    <div
      ref={fieldRef}
      aria-hidden
      className="pointer-events-none absolute inset-0 overflow-hidden"
    >
      <span className="absolute left-6 top-12 block w-11 text-[#231E1E]">
        <SnowmanMark className="h-auto w-full" />
      </span>
      {SNOW_PARTICLES.map((particle, i) => (
        <span
          key={`${particle.top}-${particle.left}`}
          ref={(el) => {
            particleRefs.current[i] = el;
          }}
          className="absolute block will-change-transform"
          style={{
            top: particle.top,
            left: particle.left,
            width: particle.size,
            color: particle.color,
            transform: `rotate(${particle.rotate}deg)`,
            opacity: 0.9,
          }}
        >
          <SnowCrystal className="w-full drop-shadow-[0_0_8px_currentColor]" />
        </span>
      ))}
    </div>
  );
}
