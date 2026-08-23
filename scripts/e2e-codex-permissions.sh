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
WARD_E2E_DEEP_REL="d1/d2/d3/d4/d5/d6/d7/d8/d9/d10"
WARD_E2E_DEEP="$WARD_E2E_WORKSPACE/$WARD_E2E_DEEP_REL"
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

mkdir -p \
  "$WARD_E2E_CODEX_DIR" \
  "$WARD_E2E_MANAGED_BIN_DIR" \
  "$WARD_E2E_WORKSPACE/nested" \
  "$WARD_E2E_WORKSPACE/schemas" \
  "$WARD_E2E_DEEP" \
  "$WARD_E2E_SIBLING" \
  "$WARD_E2E_CUSTOM_GH_DIR" \
  "$WARD_E2E_HOME/.ssh" \
  "$WARD_E2E_HOME/.docker" \
  "$WARD_E2E_HOME/.kube" \
  "$WARD_E2E_CONFIG_DIR/gcloud"
cp "$WARD_E2E_BIN" "$WARD_E2E_MANAGED_BIN"
chmod 0755 "$WARD_E2E_MANAGED_BIN"
printf '%s\n' 'approval_policy = "never"' 'sandbox_mode = "danger-full-access"' > "$WARD_E2E_CODEX_DIR/config.toml"
cp "$WARD_E2E_CODEX_DIR/config.toml" "$WARD_E2E_TMP/config.original.toml"

# Reviewed workspace secrets: the native permission profile must deny these.
printf '%s\n' 'WARD_SECRET_CANARY_7d10f7' > "$WARD_E2E_WORKSPACE/.env"
printf '%s\n' 'WARD_LOCAL_CANARY_2b98e1' > "$WARD_E2E_WORKSPACE/nested/.env.local"
printf '%s\n' 'WARD_KEY_JSON_CANARY_95d4bd' > "$WARD_E2E_WORKSPACE/app.key.json"
printf '%s\n' 'WARD_CREDENTIALS_CANARY_7f8d21' > "$WARD_E2E_WORKSPACE/nested/credentials.json"
printf '%s\n' 'WARD_SERVICE_CANARY_6259a1' > "$WARD_E2E_WORKSPACE/service-account.json"
printf '%s\n' 'WARD_YAML_CANARY_f04052' > "$WARD_E2E_WORKSPACE/nested/secrets.yml"
printf '%s\n' 'WARD_SSH_CANARY_a44071' > "$WARD_E2E_WORKSPACE/id_ed25519"
printf '%s\n' 'WARD_KEY_CANARY_f8aa11' > "$WARD_E2E_WORKSPACE/private-key.pem"
printf '%s\n' 'WARD_NUMBERED_KEY_CANARY_2f0b77' > "$WARD_E2E_WORKSPACE/privkey1.pem"
printf '%s\n' 'WARD_P12_CANARY_3f277a' > "$WARD_E2E_WORKSPACE/nested/client.p12"
printf '%s\n' 'WARD_DEEP_CANARY_b7f441' > "$WARD_E2E_DEEP/.env.production"

# Public and ordinary workspace fixtures must remain usable.
printf '%s\n' 'PUBLIC_TEMPLATE=1' > "$WARD_E2E_WORKSPACE/.env.example"
printf '%s\n' 'PUBLIC_SAMPLE=1' > "$WARD_E2E_WORKSPACE/nested/.env.sample"
printf '%s\n' 'CUSTOM_ENV=1' > "$WARD_E2E_WORKSPACE/.env.customer"
printf '%s\n' 'CUSTOM_LOCAL_ENV=1' > "$WARD_E2E_WORKSPACE/.env.customer.local"
printf '%s\n' 'ordinary' > "$WARD_E2E_WORKSPACE/ordinary.txt"
printf '%s\n' 'PUBLIC CERTIFICATE FIXTURE' > "$WARD_E2E_WORKSPACE/server.pem"
printf '%s\n' 'PUBLIC NOTES FIXTURE' > "$WARD_E2E_WORKSPACE/private-notes.pem"
printf '%s\n' 'ordinary: true' > "$WARD_E2E_WORKSPACE/deployment-secret.yml"
printf '%s\n' '{"type":"schema"}' > "$WARD_E2E_WORKSPACE/schemas/user-credential.json"
printf '%s\n' 'registry=https://example.invalid' > "$WARD_E2E_WORKSPACE/.npmrc"

# Sibling and HOME authentication stores are deliberately outside Ward's
# workspace-only Secret carve-out.
printf '%s\n' 'SIBLING_ENV=1' > "$WARD_E2E_SIBLING/.env"
printf '%s\n' 'github.com: oauth_token' > "$WARD_E2E_CUSTOM_GH_DIR/hosts.yml"
printf '%s\n' 'Host github.com' > "$WARD_E2E_HOME/.ssh/config"
printf '%s\n' 'github.com ssh-ed25519 PUBLIC' > "$WARD_E2E_HOME/.ssh/known_hosts"
printf '%s\n' 'ssh-ed25519 PUBLIC' > "$WARD_E2E_HOME/.ssh/id_ed25519.pub"
printf '%s\n' '{"auths":{}}' > "$WARD_E2E_HOME/.docker/config.json"
printf '%s\n' 'apiVersion: v1' > "$WARD_E2E_HOME/.kube/config"
printf '%s\n' '{}' > "$WARD_E2E_CONFIG_DIR/gcloud/application_default_credentials.json"

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

ward_env "$WARD_E2E_MANAGED_BIN" codex install --scope user --migrate-permissions
grep -F 'approval_policy = "never"' "$WARD_E2E_CODEX_DIR/config.toml" >/dev/null
if grep -E '^[[:space:]]*sandbox_mode[[:space:]]*=' "$WARD_E2E_CODEX_DIR/config.toml" >/dev/null; then
  printf '%s\n' 'Ward E2E: sandbox_mode remained active' >&2
  exit 1
fi
grep -F '"SessionStart"' "$WARD_E2E_CODEX_DIR/hooks.json" >/dev/null
grep -F '"PreToolUse"' "$WARD_E2E_CODEX_DIR/hooks.json" >/dev/null
if grep -E '"PermissionRequest"|"PostToolUse"|"matcher"[[:space:]]*:[[:space:]]*"\*"' "$WARD_E2E_CODEX_DIR/hooks.json" >/dev/null; then
  printf '%s\n' 'Ward E2E: legacy or wildcard Ward hook remained installed' >&2
  exit 1
fi

sandbox() {
  ward_env "$WARD_E2E_CODEX" sandbox -P ward-baseline -C "$WARD_E2E_WORKSPACE" "$@"
}

# Keep the bounded expansion depth exercised without claiming unbounded
# protection on platforms that pre-expand deny globs.
for protected in \
  .env \
  nested/.env.local \
  app.key.json \
  nested/credentials.json \
  service-account.json \
  nested/secrets.yml \
  id_ed25519 \
  private-key.pem \
  privkey1.pem \
  nested/client.p12; do
  if sandbox /bin/sh -c 'cat "$1"' sh "$protected" >/dev/null 2>&1; then
    printf 'Ward E2E: reviewed workspace Secret escaped: %s\n' "$protected" >&2
    exit 1
  fi
done

if sandbox /bin/sh -c 'cat "$1"' sh "$WARD_E2E_DEEP_REL/.env.production" >/dev/null 2>&1; then
  printf '%s\n' 'Ward E2E: depth-10 reviewed workspace Secret escaped' >&2
  exit 1
fi

for ordinary in \
  .env.example \
  nested/.env.sample \
  .env.customer \
  .env.customer.local \
  ordinary.txt \
  server.pem \
  private-notes.pem \
  deployment-secret.yml \
  schemas/user-credential.json \
  .npmrc; do
  sandbox /bin/sh -c 'cat "$1" >/dev/null && printf "updated\n" > "$1"' sh "$ordinary"
done

for auth_file in \
  "$WARD_E2E_SIBLING/.env" \
  "$WARD_E2E_CUSTOM_GH_DIR/hosts.yml" \
  "$WARD_E2E_HOME/.ssh/config" \
  "$WARD_E2E_HOME/.ssh/known_hosts" \
  "$WARD_E2E_HOME/.ssh/id_ed25519.pub" \
  "$WARD_E2E_HOME/.docker/config.json" \
  "$WARD_E2E_HOME/.kube/config" \
  "$WARD_E2E_CONFIG_DIR/gcloud/application_default_credentials.json"; do
  sandbox /bin/sh -c 'cat "$1" >/dev/null' sh "$auth_file"
done

for protected_control in "$WARD_E2E_CODEX_DIR/config.toml" "$WARD_E2E_CODEX_DIR/hooks.json" "$WARD_E2E_RESOLVED_BIN"; do
  if sandbox /bin/sh -c 'printf "tampered\n" > "$1"' sh "$protected_control" >/dev/null 2>&1; then
    printf 'Ward E2E: control-plane overwrite escaped for %s\n' "$protected_control" >&2
    exit 1
  fi
done
for protected_anchor in "$WARD_E2E_MANAGED_BIN_DIR" "$WARD_E2E_STATE_DIR/ward"; do
  if sandbox /bin/mv -- "$protected_anchor" "$protected_anchor.moved" >/dev/null 2>&1; then
    printf 'Ward E2E: protected directory relocation escaped for %s\n' "$protected_anchor" >&2
    exit 1
  fi
  test -e "$protected_anchor"
done

audit_snapshot() {
  find "$WARD_E2E_STATE_DIR/ward/v1" -type f -print | LC_ALL=C sort | while IFS= read -r file; do
    cksum "$file"
    if timestamp=$(stat -f '%m' "$file" 2>/dev/null); then
      :
    else
      timestamp=$(stat -c '%Y' "$file")
    fi
    printf '%s %s\n' "$timestamp" "$file"
  done
}

# A safe matched command must be a true zero-output, zero-audit defer.
WARD_E2E_BEFORE=$(audit_snapshot)
SAFE_PAYLOAD='{"session_id":"ward-e2e-session","cwd":"'"$WARD_E2E_WORKSPACE"'","hook_event_name":"PreToolUse","model":"gpt-test","permission_mode":"default","turn_id":"ward-e2e-safe","transcript_path":null,"tool_name":"Bash","tool_input":{"command":"cat .env"},"tool_use_id":"ward-e2e-safe-tool"}'
printf '%s' "$SAFE_PAYLOAD" | ward_env "$WARD_E2E_MANAGED_BIN" hook codex-pre-tool-use >"$WARD_E2E_TMP/safe.stdout" 2>"$WARD_E2E_TMP/safe.stderr"
test ! -s "$WARD_E2E_TMP/safe.stdout"
test ! -s "$WARD_E2E_TMP/safe.stderr"
test "$WARD_E2E_BEFORE" = "$(audit_snapshot)"

# A catastrophic request is denied once and creates one verifiable event.
DENY_PAYLOAD='{"session_id":"ward-e2e-session","cwd":"'"$WARD_E2E_WORKSPACE"'","hook_event_name":"PreToolUse","model":"gpt-test","permission_mode":"default","turn_id":"ward-e2e-deny","transcript_path":null,"tool_name":"Bash","tool_input":{"command":"rm -rf ."},"tool_use_id":"ward-e2e-deny-tool"}'
printf '%s' "$DENY_PAYLOAD" | ward_env "$WARD_E2E_MANAGED_BIN" hook codex-pre-tool-use >"$WARD_E2E_TMP/deny.stdout" 2>"$WARD_E2E_TMP/deny.stderr"
grep -F '"permissionDecision":"deny"' "$WARD_E2E_TMP/deny.stdout" >/dev/null
test ! -s "$WARD_E2E_TMP/deny.stderr"
ward_env "$WARD_E2E_MANAGED_BIN" audit verify --project "$WARD_E2E_WORKSPACE" --json | grep -F '"valid":true' >/dev/null

# Healthy SessionStart is silent; trusted Doctor stays available outside the
# guarded project sandbox.
SESSION_PAYLOAD='{"session_id":"ward-e2e-session","cwd":"'"$WARD_E2E_WORKSPACE"'","model":"gpt-test","permission_mode":"default","transcript_path":null,"hook_event_name":"SessionStart","source":"startup"}'
printf '%s' "$SESSION_PAYLOAD" | ward_env "$WARD_E2E_MANAGED_BIN" hook codex-session-start >"$WARD_E2E_TMP/session.stdout" 2>"$WARD_E2E_TMP/session.stderr"
test ! -s "$WARD_E2E_TMP/session.stdout"
test ! -s "$WARD_E2E_TMP/session.stderr"

DOCTOR_OUTPUT=$(ward_env "$WARD_E2E_MANAGED_BIN" doctor --project "$WARD_E2E_WORKSPACE" --json)
printf '%s' "$DOCTOR_OUTPUT" | grep -F '"healthy":true' >/dev/null
printf '%s' "$DOCTOR_OUTPUT" | grep -F '"id":"permissions.state_topology","status":"pass"' >/dev/null
printf '%s' "$DOCTOR_OUTPUT" | grep -F '"id":"permissions.control_topology","status":"pass"' >/dev/null
if sandbox "$WARD_E2E_MANAGED_BIN" doctor --project "$WARD_E2E_WORKSPACE" --json >/dev/null 2>&1; then
  printf '%s\n' 'Ward E2E: guarded process unexpectedly gained Doctor access to denied state' >&2
  exit 1
fi

WARD_E2E_KEY="$WARD_E2E_STATE_DIR/ward/v1/master.key"
if sandbox /bin/sh -c 'cat "$1"' sh "$WARD_E2E_KEY" >/dev/null 2>&1; then
  printf '%s\n' 'Ward E2E: Ward master key read escaped the native profile' >&2
  exit 1
fi

ward_env "$WARD_E2E_MANAGED_BIN" codex uninstall --scope user
cmp "$WARD_E2E_TMP/config.original.toml" "$WARD_E2E_CODEX_DIR/config.toml"
if [ -e "$WARD_E2E_CODEX_DIR/hooks.json" ]; then
  printf '%s\n' 'Ward E2E: uninstall did not restore absent hooks.json' >&2
  exit 1
fi
test -f "$WARD_E2E_KEY"
printf '%s\n' 'PASS: isolated Codex ambient-kernel install/defer/deny/uninstall E2E'
