# Releasing Snowman Command Center

Snowman releases are built only from an immutable, reviewed commit. The current
approved repository is `xpxpxp-coder/Igloo`; the release tooling also supports a
future move to `snowman-ai-org/snowman-command-center` without changing the
security contract.

## Change integration

Snowman maintainers use an exact-SHA direct-main path:

1. Build the change on a `codex/*` candidate branch.
2. Run local format, lint, unit, boundary, brand, supply-chain, and render gates.
3. Push the candidate and dispatch all hosted candidate workflows against that
   branch.
4. Record an independent code review and resolve every P0/P1 finding.
5. Verify every required hosted job completed successfully for the same full
   candidate SHA.
6. Fast-forward that exact SHA to `main`; never force-push `main`.
7. Verify the workflows triggered by the `main` push before creating a release
   tag or activating a deployment.

The absence of a pull request does not remove any review or test gate. Evidence
is keyed by the immutable commit SHA.

## Release lanes

| Lane | Source identity | Artifact |
|------|-----------------|----------|
| Desktop | immutable `vX.Y.Z` tag | signed/notarized installers and updater manifest |
| Relay | immutable `relay-vX.Y.Z` tag | Snowman-owned GHCR image plus provenance |
| Mobile | immutable `mobile-vX.Y.Z-rc.N` tag | platform build tied to that exact candidate |
| Helm | immutable `chart-vX.Y.Z` tag | Snowman-owned OCI chart |

Every production container and deployment manifest must use an image digest,
not `main`, `latest`, or another mutable tag.

## Candidate verification

For a candidate branch, dispatch and monitor:

```sh
gh workflow run ci.yml --repo xpxpxp-coder/Igloo --ref <candidate-branch>
gh workflow run benchmark-harbor.yml --repo xpxpxp-coder/Igloo --ref <candidate-branch>
gh workflow run helm-chart.yml --repo xpxpxp-coder/Igloo --ref <candidate-branch>
gh workflow run sprig.yml --repo xpxpxp-coder/Igloo --ref <candidate-branch>
gh workflow run snowman-production-evidence.yml --repo xpxpxp-coder/Igloo --ref <candidate-branch>
```

Confirm each run's `headSha` equals the intended full candidate SHA. A green run
for a different SHA is not release evidence.

## Desktop and relay

Desktop and relay versions remain independently controlled by
`desktop/package.json`/Tauri manifests and
`crates/buzz-relay/Cargo.toml`, respectively. The historical `buzz-*` crate and
binary names are compatibility identifiers; user-facing artifacts are Snowman.

Only tag a commit already verified on `main`. The desktop workflow signs and
notarizes macOS artifacts, signs updater artifacts, and publishes the
`snowman-command-center-latest` updater release. The relay workflow publishes
the Snowman image, SBOM, attestations, and immutable digest.

The signed macOS canary workflow is for explicit pre-release verification of
current `main`. It must never publish or move a release tag.

## Mobile candidates

Publish a mobile candidate from a clean checkout whose `origin` is an approved
Snowman repository:

```sh
scripts/mobile-release.sh candidate X.Y.Z
```

The command resolves current remote `main`, derives the next exact candidate
number, dispatches the protected tagger workflow, and verifies the resulting
annotated tag points directly to the requested commit. Existing candidate tags
must never be moved or deleted.

The Snowman-owned mobile signing lane must build the exact candidate tag and
record that tag with the App Store/Play rollout evidence. Until that lane and
its signing identities are configured, mobile production activation remains
closed.

## Required repository controls

- Protected `main` with force pushes and deletion disabled.
- Required hosted checks or equivalent exact-SHA evidence before a direct
  fast-forward.
- Active immutable release-tag rulesets.
- A least-privilege Snowman GitHub App as the only automated tag bypass actor.
- Environment-scoped signing secrets, never repository files or job output.
- Pinned third-party actions and dependency integrity checks.
- Signed images, SBOMs, provenance attestations, and digest-pinned deployment.

Mobile candidate publication requires `SNOWMAN_RELEASE_TAG_RULESET_ID` and the
Snowman release-tagger App credentials. Desktop signing additionally requires
the Tauri updater key and platform signing/notarization credentials. Missing
credentials fail closed and are irreducible operator-owned activation inputs.
While source remains in `xpxpxp-coder/Igloo`, publishing to Snowman-owned GHCR
also requires repository variable `SNOWMAN_GHCR_USERNAME` and secret
`SNOWMAN_GHCR_TOKEN` with package-write access. Pull-request jobs never receive
that credential. After migration into `snowman-ai-org`, the repository-scoped
`GITHUB_TOKEN` can be used instead when organization package policy permits it.

## Recovery and rollback

Do not move release tags. Roll back deployments by selecting a previously
verified image digest and chart version, then record the prior and replacement
digests in the incident/evidence bundle. Desktop and mobile rollbacks promote a
previously signed artifact or create a new patch release from a new reviewed
commit.

If `main` moves during candidate publication, keep any already-created immutable
tag as historical evidence and publish the next candidate number for the new
commit. Never rewrite the earlier tag.
