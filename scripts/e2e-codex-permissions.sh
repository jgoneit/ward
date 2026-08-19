#!/bin/sh
set -eu

WARD_E2E_BIN=${WARD_E2E_BIN:-"$(pwd)/bin/ward"}
WARD_E2E_CODEX=${WARD_E2E_CODEX:-codex}
WARD_E2E_TMP=$(mktemp -d "${TMPDIR:-/tmp}/ward-codex-e2e.XXXXXX")
WARD_E2E_HOME="$WARD_E2E_TMP/home"
WARD_E2E_CODEX_DIR="$WARD_E2E_HOME/.codex"
WARD_E2E_STATE_DIR="$WARD_E2E_TMP/state"
WARD_E2E_CONFIG_DIR="$WARD_E2E_HOME/.config"
WARD_E2E_CUSTOM_GH_DIR="$WARD_E2E_HOME/custom-gh"
WARD_E2E_WORKSPACE="$WARD_E2E_HOME/project-a"
WARD_E2E_SIBLING="$WARD_E2E_HOME/project-b"
WARD_E2E_MANAGED_BIN_DIR="$WARD_E2E_CODEX_DIR/ward/bin"
WARD_E2E_MANAGED_BIN="$WARD_E2E_MANAGED_BIN_DIR/ward"

cleanup() {
  chmod -R u+w "$WARD_E2E_TMP" 2>/dev/null || true
  rm -rf -- "$WARD_E2E_TMP"
}
trap cleanup EXIT HUP INT TERM

[ -x "$WARD_E2E_BIN" ] || {
  printf '%s\n' 'Ward E2E: build bin/ward first' >&2
  exit 2
}
command -v "$WARD_E2E_CODEX" >/dev/null 2>&1 || {
  printf '%s\n' 'Ward E2E: codex CLI is required' >&2
  exit 2
}

mkdir -p "$WARD_E2E_CODEX_DIR" "$WARD_E2E_MANAGED_BIN_DIR" "$WARD_E2E_WORKSPACE/nested" "$WARD_E2E_WORKSPACE/schemas" "$WARD_E2E_SIBLING" "$WARD_E2E_CUSTOM_GH_DIR"
cp "$WARD_E2E_BIN" "$WARD_E2E_MANAGED_BIN"
chmod 0755 "$WARD_E2E_MANAGED_BIN"
printf '%s\n' 'approval_policy = "never"' 'sandbox_mode = "danger-full-access"' > "$WARD_E2E_CODEX_DIR/config.toml"
cp "$WARD_E2E_CODEX_DIR/config.toml" "$WARD_E2E_TMP/config.original.toml"
printf '%s\n' 'WARD_SECRET_CANARY_7d10f7' > "$WARD_E2E_WORKSPACE/.env"
printf '%s\n' 'WARD_LOCAL_CANARY_2b98e1' > "$WARD_E2E_WORKSPACE/nested/.env.local"
printf '%s\n' 'WARD_KEY_CANARY_95d4bd' > "$WARD_E2E_WORKSPACE/private-key.pem"
printf '%s\n' 'WARD_NUMBERED_KEY_CANARY_2f0b77' > "$WARD_E2E_WORKSPACE/privkey1.pem"
printf '%s\n' 'PUBLIC_TEMPLATE=1' > "$WARD_E2E_WORKSPACE/.env.example"
printf '%s\n' 'PUBLIC_SAMPLE=1' > "$WARD_E2E_WORKSPACE/nested/.env.sample"
printf '%s\n' 'ordinary' > "$WARD_E2E_WORKSPACE/ordinary.txt"
printf '%s\n' 'WARD_SIBLING_CANARY_f1a7b3' > "$WARD_E2E_SIBLING/.env"
printf '%s\n' 'WARD_PRODUCTION_CANARY_6b0d42' > "$WARD_E2E_SIBLING/.env.production"
printf '%s\n' 'PUBLIC_SIBLING=1' > "$WARD_E2E_SIBLING/.env.example"
printf '%s\n' 'WARD_CUSTOM_GH_CANARY_4c8b21' > "$WARD_E2E_CUSTOM_GH_DIR/hosts.yml"
printf '%s\n' 'PUBLIC CERTIFICATE FIXTURE' > "$WARD_E2E_WORKSPACE/server.pem"
printf '%s\n' 'PUBLIC NOTES FIXTURE' > "$WARD_E2E_WORKSPACE/private-notes.pem"
printf '%s\n' 'PUBLIC CERTIFICATE FIXTURE' > "$WARD_E2E_WORKSPACE/private-certificate.pem"
printf '%s\n' 'PUBLIC NOTES FIXTURE' > "$WARD_E2E_WORKSPACE/privkey1-notes.pem"
printf '%s\n' '{"type":"schema"}' > "$WARD_E2E_WORKSPACE/schemas/user-credential.json"
printf '%s\n' '{"type":"schema"}' > "$WARD_E2E_WORKSPACE/schemas/credential-format.json"

WARD_E2E_BIN_DIR=$(CDPATH= cd -- "$(dirname -- "$WARD_E2E_MANAGED_BIN")" && pwd -P)
WARD_E2E_RESOLVED_BIN="$WARD_E2E_BIN_DIR/$(basename -- "$WARD_E2E_MANAGED_BIN")"

ward_env() {
  env \
    HOME="$WARD_E2E_HOME" \
    USERPROFILE="$WARD_E2E_HOME" \
    CODEX_HOME="$WARD_E2E_CODEX_DIR" \
    XDG_STATE_HOME="$WARD_E2E_STATE_DIR" \
    XDG_CONFIG_HOME="$WARD_E2E_CONFIG_DIR" \
    GH_CONFIG_DIR="$WARD_E2E_CUSTOM_GH_DIR" \
    "$@"
}

ward_env "$WARD_E2E_MANAGED_BIN" codex install --scope user --profile baseline --migrate-permissions
grep -F 'approval_policy = "never"' "$WARD_E2E_CODEX_DIR/config.toml" >/dev/null
if grep -E '^[[:space:]]*sandbox_mode[[:space:]]*=' "$WARD_E2E_CODEX_DIR/config.toml" >/dev/null; then
  printf '%s\n' 'Ward E2E: sandbox_mode remained active' >&2
  exit 1
fi

sandbox() {
  ward_env "$WARD_E2E_CODEX" sandbox -P ward-baseline -C "$WARD_E2E_WORKSPACE" "$@"
}

if sandbox /bin/sh -c 'cat .env' >/dev/null 2>&1; then
  printf '%s\n' 'Ward E2E: .env read escaped the native profile' >&2
  exit 1
fi
if sandbox /bin/sh -c 'cat nested/.env.local' >/dev/null 2>&1; then
  printf '%s\n' 'Ward E2E: nested .env.* read escaped the native profile' >&2
  exit 1
fi
if sandbox /bin/sh -c 'cat private-key.pem' >/dev/null 2>&1; then
  printf '%s\n' 'Ward E2E: private-key read escaped the native profile' >&2
  exit 1
fi
if sandbox /bin/sh -c 'cat privkey1.pem' >/dev/null 2>&1; then
  printf '%s\n' 'Ward E2E: numbered private-key read escaped the native profile' >&2
  exit 1
fi
if sandbox /bin/sh -c 'cat "$1"' sh "$WARD_E2E_SIBLING/.env" >/dev/null 2>&1; then
  printf '%s\n' 'Ward E2E: sibling .env read escaped the global native profile' >&2
  exit 1
fi
if sandbox /bin/sh -c 'cat "$1"' sh "$WARD_E2E_SIBLING/.env.production" >/dev/null 2>&1; then
  printf '%s\n' 'Ward E2E: sibling .env.production read escaped the global native profile' >&2
  exit 1
fi
if sandbox /bin/sh -c 'cat "$1"' sh "$WARD_E2E_CUSTOM_GH_DIR/hosts.yml" >/dev/null 2>&1; then
  printf '%s\n' 'Ward E2E: custom GH credential location escaped the native profile' >&2
  exit 1
fi
for protected_control in "$WARD_E2E_CODEX_DIR/config.toml" "$WARD_E2E_CODEX_DIR/hooks.json" "$WARD_E2E_RESOLVED_BIN"; do
  if sandbox /bin/sh -c 'printf "tampered\n" > "$1"' sh "$protected_control" >/dev/null 2>&1; then
    printf 'Ward E2E: control-plane overwrite escaped for %s\n' "$protected_control" >&2
    exit 1
  fi
done
for protected_anchor in "$WARD_E2E_CODEX_DIR" "$WARD_E2E_MANAGED_BIN_DIR" "$WARD_E2E_CUSTOM_GH_DIR" "$WARD_E2E_STATE_DIR/ward"; do
  if sandbox /bin/mv -- "$protected_anchor" "$protected_anchor.moved" >/dev/null 2>&1; then
    printf 'Ward E2E: protected directory relocation escaped for %s\n' "$protected_anchor" >&2
    exit 1
  fi
  test -e "$protected_anchor"
done
if sandbox /bin/sh -c 'cat "$1"' sh "$WARD_E2E_CUSTOM_GH_DIR/hosts.yml" >/dev/null 2>&1; then
  printf '%s\n' 'Ward E2E: custom credential became readable after denied directory relocation' >&2
  exit 1
fi
HOOK_OUTPUT=$(printf '%s' '{"session_id":"ward-e2e-session","cwd":"'"$WARD_E2E_WORKSPACE"'","model":"gpt-test","permission_mode":"never","turn_id":"ward-e2e-turn","transcript_path":null,"tool_name":"Bash","tool_input":{"command":"cat .env"},"tool_use_id":"ward-e2e-tool"}' | ward_env "$WARD_E2E_MANAGED_BIN" hook codex-pre-tool-use)
printf '%s' "$HOOK_OUTPUT" | grep -F '"permissionDecision":"deny"' >/dev/null
DOCTOR_OUTPUT=$(ward_env "$WARD_E2E_MANAGED_BIN" doctor --project "$WARD_E2E_WORKSPACE" --json)
printf '%s' "$DOCTOR_OUTPUT" | grep -F '"healthy":true' >/dev/null
printf '%s' "$DOCTOR_OUTPUT" | grep -F '"id":"permissions.state_topology","status":"pass"' >/dev/null
printf '%s' "$DOCTOR_OUTPUT" | grep -F '"id":"permissions.credential_topology","status":"pass"' >/dev/null
if sandbox "$WARD_E2E_MANAGED_BIN" doctor --project "$WARD_E2E_WORKSPACE" --json >/dev/null 2>&1; then
  printf '%s\n' 'Ward E2E: guarded project process unexpectedly gained Doctor access to denied control state' >&2
  exit 1
fi
sandbox /bin/sh -c 'cat .env.example >/dev/null'
sandbox /bin/sh -c 'cat nested/.env.sample >/dev/null'
sandbox /bin/sh -c 'printf "PUBLIC_TEMPLATE=2\n" > .env.example'
sandbox /bin/sh -c 'printf "PUBLIC_SAMPLE=2\n" > nested/.env.sample'
sandbox /bin/sh -c 'cat "$1" >/dev/null' sh "$WARD_E2E_SIBLING/.env.example"
sandbox /bin/sh -c 'cat ordinary.txt >/dev/null && printf "edited\n" > ordinary.txt'
for public_fixture in server.pem private-notes.pem private-certificate.pem privkey1-notes.pem schemas/user-credential.json schemas/credential-format.json; do
  sandbox /bin/sh -c 'cat "$1" >/dev/null && printf "PUBLIC FIXTURE 2\n" > "$1"' sh "$public_fixture"
done

WARD_E2E_KEY="$WARD_E2E_STATE_DIR/ward/v1/master.key"
if sandbox /bin/sh -c 'cat "$1"' sh "$WARD_E2E_KEY" >/dev/null 2>&1; then
  printf '%s\n' 'Ward E2E: Ward master key read escaped the native profile' >&2
  exit 1
fi

ward_env "$WARD_E2E_MANAGED_BIN" codex uninstall --scope user --profile baseline
cmp "$WARD_E2E_TMP/config.original.toml" "$WARD_E2E_CODEX_DIR/config.toml"
if [ -e "$WARD_E2E_CODEX_DIR/hooks.json" ]; then
  printf '%s\n' 'Ward E2E: uninstall did not restore absent hooks.json' >&2
  exit 1
fi
test -f "$WARD_E2E_KEY"
printf '%s\n' 'PASS: isolated Codex permission install/read/write/uninstall E2E'
