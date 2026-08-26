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

printf '%s\n' 'PASS: POSIX binary-only uninstall covered structural Ward references and near misses'
