# Snowman UI accessibility and performance gate

This gate covers the production-critical Command Center shell, governed huddle
and agent status, browser repository experience, operations console, and mobile
agent activity observer. It does not replace manual assistive-technology UAT.

## Automated acceptance

- Desktop, browser, and operations surfaces expose a keyboard-reachable skip
  link targeting a focusable main landmark.
- Huddle/model state and agent work state use polite, atomic live regions;
  errors use alert semantics and decorative progress icons are hidden.
- Browser and operations focus indicators remain visible, loading states expose
  busy/status semantics, and reduced-motion preferences collapse nonessential
  animation and smooth scrolling.
- Mobile agent activity avoids animated autoscroll when animations are disabled
  and announces connection, waiting, and error state changes as live regions.
- Production builds enforce gzip entry, total-JavaScript, and asset-count
  budgets through `scripts/check-snowman-ui-budgets.mjs`.
- `pnpm ui:accessibility` prevents removal of these structural guarantees.

## Residual manual UAT before activation

Test desktop and web with keyboard only at 200% zoom and with VoiceOver/NVDA;
test mobile with VoiceOver/TalkBack and large text; verify huddle join, model
download, agent-working, tool progress, disconnect, failure, and recovery
announcements without repeated speech; run light/dark contrast review at the
token level; and confirm the measured command-center startup/interaction SLOs
on staged release hardware. Record browser/OS/app version and evidence artifact
digests in the launch bundle.
