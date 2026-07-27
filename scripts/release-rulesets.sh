#!/usr/bin/env bash

readonly SNOWMAN_RELEASE_REPOSITORY="${SNOWMAN_RELEASE_REPOSITORY:-${GITHUB_REPOSITORY:-xpxpxp-coder/Igloo}}"
readonly RELEASE_TAG_RULESET_ID="${SNOWMAN_RELEASE_TAG_RULESET_ID:-}"

case "$SNOWMAN_RELEASE_REPOSITORY" in
  xpxpxp-coder/Igloo|snowman-ai-org/snowman-command-center) ;;
  *)
    echo "Error: unsupported Snowman release repository '$SNOWMAN_RELEASE_REPOSITORY'" >&2
    return 1 2>/dev/null || exit 1
    ;;
esac

fail_release_ruleset() {
  echo "Error: $*" >&2
  return 1
}

require_release_repository() {
  local origin_url

  origin_url="$(git config --get remote.origin.url 2>/dev/null)" || \
    fail_release_ruleset "origin is required and must point to $SNOWMAN_RELEASE_REPOSITORY" || return 1
  case "$origin_url" in
    "git@github.com:${SNOWMAN_RELEASE_REPOSITORY}.git"|"ssh://git@github.com/${SNOWMAN_RELEASE_REPOSITORY}.git"|"https://github.com/${SNOWMAN_RELEASE_REPOSITORY}.git"|"https://github.com/${SNOWMAN_RELEASE_REPOSITORY}")
      ;;
    *)
      fail_release_ruleset "origin must point to approved Snowman release repository $SNOWMAN_RELEASE_REPOSITORY, not '$origin_url'" || return 1
      ;;
  esac
}

require_release_tag_ruleset() {
  local ruleset_endpoint state can_bypass rule_types includes excludes

  command -v gh >/dev/null 2>&1 || fail_release_ruleset "gh is required" || return 1
  [[ "$RELEASE_TAG_RULESET_ID" =~ ^[1-9][0-9]*$ ]] || \
    fail_release_ruleset "SNOWMAN_RELEASE_TAG_RULESET_ID must name the Snowman repository's active release ruleset" || return 1
  ruleset_endpoint="repos/$SNOWMAN_RELEASE_REPOSITORY/rulesets/$RELEASE_TAG_RULESET_ID"

  state="$(gh api "$ruleset_endpoint" --jq .enforcement)" || \
    fail_release_ruleset "could not verify Release tag ruleset $RELEASE_TAG_RULESET_ID" || return 1
  [[ "$state" == "active" ]] || \
    fail_release_ruleset "Release tag ruleset $RELEASE_TAG_RULESET_ID is '$state'" || return 1

  can_bypass="$(gh api "$ruleset_endpoint" --jq .current_user_can_bypass)" || \
    fail_release_ruleset "could not verify the release App's tag-ruleset bypass" || return 1
  [[ "$can_bypass" == "always" ]] || \
    fail_release_ruleset "release App cannot always bypass Release tag ruleset $RELEASE_TAG_RULESET_ID (reported '$can_bypass')" || return 1

  rule_types="$(gh api "$ruleset_endpoint" --jq '[.rules[].type] | sort | join(",")')" || \
    fail_release_ruleset "could not verify Release tag ruleset $RELEASE_TAG_RULESET_ID rules" || return 1
  [[ "$rule_types" == "creation,deletion,non_fast_forward,update" ]] || \
    fail_release_ruleset "Release tag ruleset $RELEASE_TAG_RULESET_ID has unexpected rules: '$rule_types'" || return 1

  includes="$(gh api "$ruleset_endpoint" --jq '[.conditions.ref_name.include[]] | sort | join(",")')" || \
    fail_release_ruleset "could not verify Release tag ruleset $RELEASE_TAG_RULESET_ID scope" || return 1
  [[ ",$includes," == *",refs/tags/mobile-v*,"* ]] || \
    fail_release_ruleset "Release tag ruleset $RELEASE_TAG_RULESET_ID does not include refs/tags/mobile-v*" || return 1

  excludes="$(gh api "$ruleset_endpoint" --jq '[.conditions.ref_name.exclude[]] | sort | join(",")')" || \
    fail_release_ruleset "could not verify Release tag ruleset $RELEASE_TAG_RULESET_ID exclusions" || return 1
  [[ -z "$excludes" ]] || \
    fail_release_ruleset "Release tag ruleset $RELEASE_TAG_RULESET_ID has unexpected exclusions: '$excludes'" || return 1
}
