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
if [ "$WARD_TEST_LEGACY_EXIT" -eq 0 ]; then
  printf '%s\n' 'Ward binary-only uninstall test: missing binary ignored a legacy Ward hook' >&2
  exit 1
fi
grep -Fq 'codex-permission-request' "$WARD_TEST_HOOKS"
grep -Fq 'Ward hook or config references remain' "$WARD_TEST_TEMP/legacy.stderr"

printf '%s\n' 'PASS: POSIX binary-only uninstall preserved config and detected legacy hooks'
