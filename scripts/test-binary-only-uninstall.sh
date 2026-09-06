#!/bin/sh
set -eu

WARD_TEST_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
WARD_TEST_SOURCE_BINARY=${1:-"$WARD_TEST_ROOT/ward"}
WARD_TEST_TEMP=$(mktemp -d "${TMPDIR:-/tmp}/ward-binary-only-uninstall.XXXXXX")
WARD_TEST_USER_HOME="$WARD_TEST_TEMP/home"
WARD_TEST_CODEX_HOME="$WARD_TEST_USER_HOME/.codex"
WARD_TEST_INSTALL_DIR="$WARD_TEST_CODEX_HOME/ward/bin"
WARD_TEST_BINARY="$WARD_TEST_INSTALL_DIR/ward"
WARD_TEST_STATE_HOME="$WARD_TEST_TEMP/state"
WARD_TEST_XDG_CONFIG_HOME="$WARD_TEST_TEMP/custom config"
WARD_TEST_CONFIG="$WARD_TEST_CODEX_HOME/config.toml"
WARD_TEST_CONFIG_BEFORE="$WARD_TEST_TEMP/config.before.toml"
WARD_TEST_HOOKS="$WARD_TEST_CODEX_HOME/hooks.json"
WARD_TEST_JOURNAL="$WARD_TEST_STATE_HOME/ward/core/integration-journal.json"

cleanup() {
  chmod -R u+w "$WARD_TEST_TEMP" 2>/dev/null || true
  rm -rf -- "$WARD_TEST_TEMP"
}
trap cleanup EXIT HUP INT TERM

[ -f "$WARD_TEST_SOURCE_BINARY" ] && [ -x "$WARD_TEST_SOURCE_BINARY" ] || {
  printf 'Ward binary-only uninstall test: executable is unavailable: %s\n' "$WARD_TEST_SOURCE_BINARY" >&2
  exit 2
}

mkdir -p "$WARD_TEST_INSTALL_DIR"
cp "$WARD_TEST_SOURCE_BINARY" "$WARD_TEST_BINARY"
chmod 0755 "$WARD_TEST_BINARY"
printf '%s\n' 'approval_policy = "never"' 'model = "gpt-test"' > "$WARD_TEST_CONFIG"
cp "$WARD_TEST_CONFIG" "$WARD_TEST_CONFIG_BEFORE"

test ! -e "$WARD_TEST_HOOKS"
test ! -e "$WARD_TEST_JOURNAL"

set +e
env \
  HOME="$WARD_TEST_USER_HOME" \
  USERPROFILE="$WARD_TEST_USER_HOME" \
  CODEX_HOME="$WARD_TEST_CODEX_HOME" \
  WARD_INSTALL_DIR="$WARD_TEST_INSTALL_DIR" \
  XDG_STATE_HOME="$WARD_TEST_STATE_HOME" \
  XDG_CONFIG_HOME="$WARD_TEST_XDG_CONFIG_HOME" \
  "$WARD_TEST_ROOT/uninstall.sh" >"$WARD_TEST_TEMP/uninstall.stdout" 2>"$WARD_TEST_TEMP/uninstall.stderr"
WARD_TEST_EXIT=$?
set -e

if [ "$WARD_TEST_EXIT" -ne 0 ]; then
  sed -n '1,20p' "$WARD_TEST_TEMP/uninstall.stdout" >&2
  sed -n '1,20p' "$WARD_TEST_TEMP/uninstall.stderr" >&2
  printf 'Ward binary-only uninstall test: uninstaller exited %s\n' "$WARD_TEST_EXIT" >&2
  exit 1
fi
test ! -e "$WARD_TEST_BINARY"
cmp "$WARD_TEST_CONFIG_BEFORE" "$WARD_TEST_CONFIG"
test ! -e "$WARD_TEST_HOOKS"
test ! -e "$WARD_TEST_JOURNAL"
test ! -e "$WARD_TEST_STATE_HOME"

printf '%s\n' '{"hooks":{"PermissionRequest":[{"matcher":"*","hooks":[{"type":"command","command":"ward hook codex-permission-request","timeout":10}]}]}}' > "$WARD_TEST_HOOKS"
cp "$WARD_TEST_HOOKS" "$WARD_TEST_TEMP/legacy.hooks.before"
set +e
env \
  HOME="$WARD_TEST_USER_HOME" \
  USERPROFILE="$WARD_TEST_USER_HOME" \
  CODEX_HOME="$WARD_TEST_CODEX_HOME" \
  WARD_INSTALL_DIR="$WARD_TEST_INSTALL_DIR" \
  XDG_STATE_HOME="$WARD_TEST_STATE_HOME" \
  XDG_CONFIG_HOME="$WARD_TEST_XDG_CONFIG_HOME" \
  "$WARD_TEST_ROOT/uninstall.sh" >"$WARD_TEST_TEMP/legacy.stdout" 2>"$WARD_TEST_TEMP/legacy.stderr"
WARD_TEST_LEGACY_EXIT=$?
set -e
if [ "$WARD_TEST_LEGACY_EXIT" -ne 1 ]; then
  printf 'Ward binary-only uninstall test: legacy Ward hook returned %s, want 1\n' "$WARD_TEST_LEGACY_EXIT" >&2
  exit 1
fi
cmp "$WARD_TEST_TEMP/legacy.hooks.before" "$WARD_TEST_HOOKS"
cmp "$WARD_TEST_CONFIG_BEFORE" "$WARD_TEST_CONFIG"
grep -Fq 'Ward hook or config references remain' "$WARD_TEST_TEMP/legacy.stderr"
test ! -e "$WARD_TEST_JOURNAL"
test ! -e "$WARD_TEST_STATE_HOME"

printf '%s\n' '{"hooks":{}}' > "$WARD_TEST_HOOKS"

assert_config_case() {
  WARD_TEST_CASE_ID=$1
  WARD_TEST_CASE_EXPECTATION=$2
  WARD_TEST_CASE_DESCRIPTION=$3
  shift 3

  printf '%s\n' "$@" > "$WARD_TEST_CONFIG"
  cp "$WARD_TEST_CONFIG" "$WARD_TEST_TEMP/$WARD_TEST_CASE_ID.config.before"
  cp "$WARD_TEST_HOOKS" "$WARD_TEST_TEMP/$WARD_TEST_CASE_ID.hooks.before"

  set +e
  env \
    HOME="$WARD_TEST_USER_HOME" \
    USERPROFILE="$WARD_TEST_USER_HOME" \
    CODEX_HOME="$WARD_TEST_CODEX_HOME" \
    WARD_INSTALL_DIR="$WARD_TEST_INSTALL_DIR" \
    XDG_STATE_HOME="$WARD_TEST_STATE_HOME" \
    XDG_CONFIG_HOME="$WARD_TEST_XDG_CONFIG_HOME" \
    "$WARD_TEST_ROOT/uninstall.sh" >"$WARD_TEST_TEMP/$WARD_TEST_CASE_ID.stdout" 2>"$WARD_TEST_TEMP/$WARD_TEST_CASE_ID.stderr"
  WARD_TEST_CASE_EXIT=$?
  set -e

  case "$WARD_TEST_CASE_EXPECTATION" in
    refuse)
      if [ "$WARD_TEST_CASE_EXIT" -ne 1 ]; then
        printf 'Ward binary-only uninstall test: %s returned %s, want 1\n' "$WARD_TEST_CASE_DESCRIPTION" "$WARD_TEST_CASE_EXIT" >&2
        exit 1
      fi
      grep -Fq 'Ward hook or config references remain' "$WARD_TEST_TEMP/$WARD_TEST_CASE_ID.stderr"
      ;;
    absent)
      if [ "$WARD_TEST_CASE_EXIT" -ne 0 ]; then
        sed -n '1,20p' "$WARD_TEST_TEMP/$WARD_TEST_CASE_ID.stderr" >&2
        printf 'Ward binary-only uninstall test: %s returned %s, want 0\n' "$WARD_TEST_CASE_DESCRIPTION" "$WARD_TEST_CASE_EXIT" >&2
        exit 1
      fi
      grep -Fq 'Ward integration is already absent' "$WARD_TEST_TEMP/$WARD_TEST_CASE_ID.stdout"
      ;;
    *)
      printf 'Ward binary-only uninstall test: unknown expectation %s\n' "$WARD_TEST_CASE_EXPECTATION" >&2
      exit 2
      ;;
  esac

  cmp "$WARD_TEST_TEMP/$WARD_TEST_CASE_ID.config.before" "$WARD_TEST_CONFIG"
  cmp "$WARD_TEST_TEMP/$WARD_TEST_CASE_ID.hooks.before" "$WARD_TEST_HOOKS"
  test ! -e "$WARD_TEST_BINARY"
  test ! -e "$WARD_TEST_JOURNAL"
  test ! -e "$WARD_TEST_STATE_HOME"
}

assert_config_case legacy-profile refuse 'legacy Ward profile' \
  '"default_permissions" = "ward-baseline"' \
  '[ permissions . ward-baseline . filesystem ]'
assert_config_case single-selector refuse 'single-quoted Ward selector' \
  "default_permissions = 'ward'"
assert_config_case double-quoted-profile refuse 'double-quoted Ward profile key' \
  '[permissions."ward"]'
assert_config_case single-quoted-profile refuse 'single-quoted Ward profile key' \
  "[ 'permissions' . 'ward-baseline' . network ]"
assert_config_case child-profile refuse 'Ward child profile reference' \
  'extends = "ward"'
assert_config_case future-marker refuse 'version-independent Ward marker' \
  '# >>> ward permission profile v99 >>>'
assert_config_case legacy-marker refuse 'v1 Ward marker' \
  '# ward:migrated-sandbox-mode:v1'
assert_config_case near-misses absent 'non-Ward near matches' \
  '[projects."/Users/name/plugins/ward"]' \
  'enabled_plugins = ["ward@personal"]' \
  'note = "hospital ward config"' \
  'name = "forward"' \
  'other = "wardrobe"' \
  'profile = "my_ward"' \
  'permission = "ward-extra"' \
  'default_permissions = "WARD"' \
  '[permissions.ward-baseline-extra]'

assert_diagnostics_case() {
  WARD_TEST_DIAGNOSTIC_ID=$1
  WARD_TEST_DIAGNOSTIC_EXPECTATION=$2
  WARD_TEST_DIAGNOSTIC_ARTIFACT=$3
  mkdir -p "$(dirname -- "$WARD_TEST_DIAGNOSTIC_ARTIFACT")" "$WARD_TEST_STATE_HOME" "$WARD_TEST_XDG_CONFIG_HOME"
  printf '%s\n' 'preserve diagnostics fixture bytes' > "$WARD_TEST_DIAGNOSTIC_ARTIFACT"

  # Include every fixture file so refusal also detects unrelated deletions,
  # new persistent files, and config/hook changes. Captured output is outside
  # the user home and state tree being checked.
  find "$WARD_TEST_USER_HOME" "$WARD_TEST_STATE_HOME" "$WARD_TEST_XDG_CONFIG_HOME" -type f -exec cksum {} \; | LC_ALL=C sort > "$WARD_TEST_TEMP/diagnostics.before"
  set +e
  env \
    HOME="$WARD_TEST_USER_HOME" \
    USERPROFILE="$WARD_TEST_USER_HOME" \
    CODEX_HOME="$WARD_TEST_CODEX_HOME" \
    WARD_INSTALL_DIR="$WARD_TEST_INSTALL_DIR" \
    XDG_STATE_HOME="$WARD_TEST_STATE_HOME" \
    XDG_CONFIG_HOME="$WARD_TEST_XDG_CONFIG_HOME" \
    "$WARD_TEST_ROOT/uninstall.sh" >"$WARD_TEST_TEMP/$WARD_TEST_DIAGNOSTIC_ID.stdout" 2>"$WARD_TEST_TEMP/$WARD_TEST_DIAGNOSTIC_ID.stderr"
  WARD_TEST_DIAGNOSTIC_EXIT=$?
  set -e

  case "$WARD_TEST_DIAGNOSTIC_EXPECTATION" in
    refuse)
      test "$WARD_TEST_DIAGNOSTIC_EXIT" -eq 1 || {
        printf 'Ward binary-only uninstall test: diagnostics %s returned %s, want 1\n' "$WARD_TEST_DIAGNOSTIC_ID" "$WARD_TEST_DIAGNOSTIC_EXIT" >&2
        exit 1
      }
      grep -Fq 'diagnostics artifacts remain' "$WARD_TEST_TEMP/$WARD_TEST_DIAGNOSTIC_ID.stderr"
      ;;
    absent)
      test "$WARD_TEST_DIAGNOSTIC_EXIT" -eq 0 || {
        sed -n '1,20p' "$WARD_TEST_TEMP/$WARD_TEST_DIAGNOSTIC_ID.stderr" >&2
        printf 'Ward binary-only uninstall test: harmless %s was refused\n' "$WARD_TEST_DIAGNOSTIC_ID" >&2
        exit 1
      }
      grep -Fq 'Ward integration is already absent' "$WARD_TEST_TEMP/$WARD_TEST_DIAGNOSTIC_ID.stdout"
      ;;
  esac
  find "$WARD_TEST_USER_HOME" "$WARD_TEST_STATE_HOME" "$WARD_TEST_XDG_CONFIG_HOME" -type f -exec cksum {} \; | LC_ALL=C sort > "$WARD_TEST_TEMP/diagnostics.after"
  cmp "$WARD_TEST_TEMP/diagnostics.before" "$WARD_TEST_TEMP/diagnostics.after"
  test ! -e "$WARD_TEST_BINARY"
  test ! -e "$WARD_TEST_JOURNAL"
  rm -- "$WARD_TEST_DIAGNOSTIC_ARTIFACT"
}

WARD_TEST_DIAGNOSTIC_STATE="$WARD_TEST_STATE_HOME/ward/core/diagnostics"
case "$(uname -s)" in
  Darwin) WARD_TEST_DIAGNOSTIC_HASH=$(printf '%s\000%s' "$(id -u)" "$WARD_TEST_BINARY" | /usr/bin/shasum -a 256) ;;
  Linux) WARD_TEST_DIAGNOSTIC_HASH=$(printf '%s\000%s' "$(id -u)" "$WARD_TEST_BINARY" | sha256sum) ;;
  *) printf '%s\n' 'unsupported POSIX test platform' >&2; exit 2 ;;
esac
WARD_TEST_DIAGNOSTIC_SUFFIX=$(printf '%.24s' "$WARD_TEST_DIAGNOSTIC_HASH")
WARD_TEST_OTHER_SUFFIX=000000000000000000000000
test "$WARD_TEST_DIAGNOSTIC_SUFFIX" != "$WARD_TEST_OTHER_SUFFIX"
assert_diagnostics_case collector-copy refuse "$WARD_TEST_INSTALL_DIR/ward-diagnostics"
assert_diagnostics_case ownership-manifest refuse "$WARD_TEST_DIAGNOSTIC_STATE/service-owner.json"
assert_diagnostics_case runtime-descriptor refuse "$WARD_TEST_DIAGNOSTIC_STATE/runtime.json"
assert_diagnostics_case heartbeat refuse "$WARD_TEST_DIAGNOSTIC_STATE/heartbeat.json"
assert_diagnostics_case launchagent refuse "$WARD_TEST_USER_HOME/Library/LaunchAgents/io.github.jgoneit.ward.diagnostics.$WARD_TEST_DIAGNOSTIC_SUFFIX.plist"
assert_diagnostics_case systemd-service refuse "$WARD_TEST_XDG_CONFIG_HOME/systemd/user/ward-diagnostics-$WARD_TEST_DIAGNOSTIC_SUFFIX.service"
assert_diagnostics_case unrelated-launchagent absent "$WARD_TEST_USER_HOME/Library/LaunchAgents/io.github.jgoneit.ward.diagnostics.$WARD_TEST_OTHER_SUFFIX.plist"
assert_diagnostics_case unrelated-systemd absent "$WARD_TEST_XDG_CONFIG_HOME/systemd/user/ward-diagnostics-$WARD_TEST_OTHER_SUFFIX.service"
assert_diagnostics_case unselected-config-root absent "$WARD_TEST_USER_HOME/.config/systemd/user/ward-diagnostics-$WARD_TEST_DIAGNOSTIC_SUFFIX.service"
assert_diagnostics_case management-lock absent "$WARD_TEST_DIAGNOSTIC_STATE/management.lock"
assert_diagnostics_case collector-lock absent "$WARD_TEST_DIAGNOSTIC_STATE/collector.lock"
assert_diagnostics_case retained-log absent "$WARD_TEST_STATE_HOME/ward/diagnostics/events-retained.jsonl"

printf '%s\n' 'PASS: POSIX binary-only uninstall covered structural references, surviving diagnostics artifacts, and harmless retained state'
