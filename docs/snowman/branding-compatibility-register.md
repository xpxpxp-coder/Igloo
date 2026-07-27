# Snowman product identity and compatibility register

## Product authority

`product/identity.json` and `product/design-tokens.json` are the canonical
product and visual identity sources. `scripts/generate-snowman-product.mjs`
materializes checked TypeScript, CSS, and Dart constants for desktop, browser,
operations, and mobile surfaces. Generated files are never edited directly;
`--check` fails when a surface drifts from the source.

The Snowman palette uses midnight/ice surfaces, glacier blue for primary
action and focus, aurora for positive state, ember for narrowly used attention,
and explicit light/dark semantic tokens. Inter and Geist Mono remain the shared
type families. Motion tokens must honor reduced-motion preferences.

## Compatibility identifiers retained internally

These identifiers may remain while their rendered labels and endpoints are
Snowman. They do not authorize an upstream connection.

| Identifier | Reason | User-facing treatment | Removal condition |
| --- | --- | --- | --- |
| Nostr event kinds and signed field names | Wire compatibility and existing signature semantics | Document as signed Snowman actions where explanation is needed | Never rename if it would invalidate compatibility or signatures. |
| `BUZZ_*` environment variables | Deployment compatibility with the fork and local tooling | Snowman runbooks describe their purpose; values point only to Snowman resources | Add aliases and deprecate only through a versioned migration. |
| Rust crate/binary names such as `buzz-relay`, `buzz-db`, `buzz-agent` | Large internal dependency graph and protocol tooling | Product/CLI help, image metadata, services, and operations labels render Snowman | Add Snowman wrapper names before optional internal package migration. |
| `buzz` / `buzz-dark` persisted theme values | Existing user preference storage | Render as “Snowman Ice,” “Snowman Midnight,” or “Snowman” | Migrate storage with backward read support. |
| `buzz://` deep links | Read-only links issued by older installs | `snowman://` is primary; legacy scheme is accepted but never generated | Remove only after a measured deprecation window. |
| `buzz-*` local-storage and migration markers | Prevents data loss and duplicate migrations | Never shown to users | Replace only with read-old/write-new migration tests. |
| Legacy desktop process names (`Buzz`, `buzz-desktop`) | Safe orphan-agent cleanup must recognize an older process during an in-place upgrade | Never shown to users; new process names are Snowman Command Center | Remove only after the supported upgrade window and process-lifecycle tests prove it safe. |
| Built-in persona IDs such as `builtin:fizz` | Existing agent/team references and user customization preservation | Persona presentation will migrate separately with alias-aware records | Complete a non-destructive persona migration and UAT. |
| Dart package name `buzz` | Internal import namespace across the inherited mobile source | App name, bundle ID, icons, copy, links, and store metadata are Snowman | Rename after generated import migration can prove a clean build. |
| `~/.buzz`, `.buzz-dev`, and `.agents/skills/buzz-cli` | Existing agent workspace and skill locations contain persistent user work and harness symlinks | Workspace headings and skill descriptions render Snowman; the installed executable remains `buzz` | Add read-old/write-new relocation with rollback and symlink tests before changing paths. |
| Helm chart/package ID and template helpers named `buzz` | Existing values files, releases, selectors, and upgrade history bind this package ID | Chart descriptions, notes, maintainers, images, and operator docs render Snowman Command Center | Publish a versioned chart alias and prove in-place Helm upgrade before renaming the chart/helper IDs. |
| Managed-section markers containing `BUZZ` | Existing generated workspace files use these exact delimiters to preserve human-authored content | Never rendered as a product label; generated headings and instructions are Snowman | Dual-read marker migration proves no custom workspace content is lost. |

## Not compatibility exceptions

Upstream endpoints, Block registries, Buzz/Sprout display copy, bee/hive artwork,
mutable image defaults, deployment names, installers, application/store metadata,
docs, alerts, dashboards, and support/legal surfaces are not protocol
requirements. They must migrate to Snowman or be explicitly disabled before
release.

The development Compose project, containers, networks, labels, and named
volumes use `snowman-command-center-*`. The prior `buzz-*` development volumes
are not deleted by this migration; they remain recoverable for an operator who
needs to copy local-only data into the new development volumes. Production data
must never be migrated through the development Compose topology.
