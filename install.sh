#!/bin/sh
set -eu

repo="jgoneit/ward"
version=""
codex_dir=${CODEX_HOME:-"$HOME/.codex"}
install_dir=${WARD_INSTALL_DIR:-"$codex_dir/ward/bin"}
state_base=${XDG_STATE_HOME:-"$HOME/.local/state"}

usage() {
  printf '%s\n' 'usage: install.sh --version vX.Y.Z [--install-dir PATH]'
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      version=$2
      shift 2
      ;;
    --install-dir)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      install_dir=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

codex_dir=${codex_dir%/}
install_dir=${install_dir%/}
[ -n "$version" ] || { usage >&2; exit 2; }
case "$codex_dir" in
  /*) ;;
  *) printf '%s\n' 'ward installer: CODEX_HOME must be absolute' >&2; exit 2 ;;
esac
case "$state_base" in
  /*) ;;
  *) printf '%s\n' 'ward installer: XDG_STATE_HOME must be absolute' >&2; exit 2 ;;
esac
case "/$codex_dir/$install_dir/" in
  *"/../"*|*"/./"*) printf '%s\n' 'ward installer: control paths must not contain dot traversal components' >&2; exit 2 ;;
esac
[ "$(dirname -- "$codex_dir")" = "$HOME" ] || {
  printf '%s\n' 'ward installer: v0.1 requires CODEX_HOME directly below HOME' >&2
  exit 2
}
case "$install_dir" in
  "$codex_dir"/*) ;;
  *) printf '%s\n' 'ward installer: --install-dir must remain below CODEX_HOME' >&2; exit 2 ;;
esac
control_cursor=$install_dir
while :; do
  if [ -L "$control_cursor" ]; then
    printf 'ward installer: control path must not contain a symbolic link: %s\n' "$control_cursor" >&2
    exit 2
  fi
  [ "$control_cursor" != "$codex_dir" ] || break
  control_parent=$(dirname -- "$control_cursor")
  [ "$control_parent" != "$control_cursor" ] || {
    printf '%s\n' 'ward installer: could not validate the CODEX_HOME control chain' >&2
    exit 2
  }
  control_cursor=$control_parent
done
printf '%s\n' "$version" | LC_ALL=C grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || {
  printf '%s\n' 'ward installer: --version must be an explicit vX.Y.Z tag' >&2
  exit 2
}

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) printf '%s\n' 'ward installer: unsupported operating system' >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) printf '%s\n' 'ward installer: unsupported architecture' >&2; exit 1 ;;
esac

command -v curl >/dev/null 2>&1 || { printf '%s\n' 'ward installer: curl is required' >&2; exit 1; }

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/ward-install.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

plain_version=${version#v}
archive="ward_${plain_version}_${os}_${arch}.tar.gz"
base_url="https://github.com/${repo}/releases/download/${version}"
curl --fail --location --silent --show-error --output "$tmp_dir/$archive" "$base_url/$archive"
curl --fail --location --silent --show-error --output "$tmp_dir/checksums.txt" "$base_url/checksums.txt"

expected=$(awk -v name="$archive" '$2 == name || $2 == "*" name { print $1; exit }' "$tmp_dir/checksums.txt")
[ -n "$expected" ] || { printf '%s\n' 'ward installer: archive checksum is missing' >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp_dir/$archive" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$tmp_dir/$archive" | awk '{print $1}')
fi
[ "$actual" = "$expected" ] || { printf '%s\n' 'ward installer: checksum mismatch' >&2; exit 1; }

tar -xzf "$tmp_dir/$archive" -C "$tmp_dir"
[ -x "$tmp_dir/ward" ] || { printf '%s\n' 'ward installer: archive does not contain ward' >&2; exit 1; }
[ "$("$tmp_dir/ward" --version)" = "ward $plain_version" ] || {
  printf '%s\n' 'ward installer: binary version does not match requested tag' >&2
  exit 1
}

mkdir -p "$install_dir"
ward_binary="$install_dir/ward"
previous_binary="$tmp_dir/ward.previous"
hooks_file="$codex_dir/hooks.json"
config_file="$codex_dir/config.toml"
journal_file="${state_base%/}/ward/core/integration-journal.json"
previous_hooks="$tmp_dir/hooks.previous"
previous_config="$tmp_dir/config.previous"
previous_journal="$tmp_dir/journal.previous"
had_previous=0
if [ -e "$ward_binary" ] || [ -L "$ward_binary" ]; then
  if [ -L "$ward_binary" ] || [ ! -f "$ward_binary" ]; then
    printf 'ward installer: refusing non-regular existing binary at %s\n' "$ward_binary" >&2
    exit 1
  fi
  cp -p "$ward_binary" "$previous_binary"
  had_previous=1
fi

snapshot_control_file() {
  snapshot_path=$1
  snapshot_backup=$2
  if [ -e "$snapshot_path" ] || [ -L "$snapshot_path" ]; then
    if [ -L "$snapshot_path" ] || [ ! -f "$snapshot_path" ]; then
      printf 'ward installer: refusing non-regular integration file at %s\n' "$snapshot_path" >&2
      return 1
    fi
    cp -p "$snapshot_path" "$snapshot_backup"
    printf '%s\n' present
  else
    printf '%s\n' absent
  fi
}

hooks_presence=$(snapshot_control_file "$hooks_file" "$previous_hooks")
config_presence=$(snapshot_control_file "$config_file" "$previous_config")
journal_presence=$(snapshot_control_file "$journal_file" "$previous_journal")

file_mode() {
  case "$os" in
    darwin) stat -f '%Lp' "$1" ;;
    linux) stat -c '%a' "$1" ;;
  esac
}

restore_control_file() {
  restore_path=$1
  restore_backup=$2
  restore_presence=$3
  if [ "$restore_presence" = present ]; then
    restore_parent=$(dirname -- "$restore_path")
    restore_candidate="$restore_path.ward-restore.$$"
    if ! mkdir -p "$restore_parent" ||
       ! cp -p "$restore_backup" "$restore_candidate" ||
       ! mv -f "$restore_candidate" "$restore_path" ||
       ! cmp -s "$restore_backup" "$restore_path" ||
       [ "$(file_mode "$restore_backup")" != "$(file_mode "$restore_path")" ]; then
      printf 'ward installer: failed to restore integration file %s\n' "$restore_path" >&2
      return 1
    fi
  else
    if ! rm -f "$restore_path" || [ -e "$restore_path" ] || [ -L "$restore_path" ]; then
      printf 'ward installer: failed to restore absence of integration file %s\n' "$restore_path" >&2
      return 1
    fi
  fi
}

restore_previous_binary() {
  restore_candidate="$install_dir/.ward.restore.$$"
  if [ "$had_previous" -eq 1 ]; then
    if ! cp -p "$previous_binary" "$restore_candidate" || ! mv -f "$restore_candidate" "$ward_binary"; then
      printf '%s\n' 'ward installer: failed to restore the previous binary state' >&2
      return 1
    fi
  else
    if ! rm -f "$ward_binary"; then
      printf '%s\n' 'ward installer: failed to restore the previous binary state' >&2
      return 1
    fi
  fi
}

restore_installation_snapshot() {
  # Restore integration bytes before the binary. If any data restoration
  # fails, the new verified binary remains runnable for recovery.
  if ! restore_control_file "$hooks_file" "$previous_hooks" "$hooks_presence" ||
     ! restore_control_file "$config_file" "$previous_config" "$config_presence" ||
     ! restore_control_file "$journal_file" "$previous_journal" "$journal_presence"; then
    printf '%s\n' 'ward installer: exact Core snapshot restoration failed; the new binary was preserved for recovery' >&2
    return 1
  fi
  restore_previous_binary
}

candidate="$install_dir/.ward.new.$$"
cp "$tmp_dir/ward" "$candidate"
chmod 0755 "$candidate"
if ! mv -f "$candidate" "$ward_binary"; then
  restore_previous_binary
  printf '%s\n' 'ward installer: binary replacement failed; the previous binary state was restored' >&2
  exit 1
fi
printf 'installed Ward %s at %s\n' "$version" "$ward_binary"

preflight_out="$tmp_dir/codex-install-preflight.json"
preflight_err="$tmp_dir/codex-install-preflight.err"
if "$ward_binary" codex install --scope user --dry-run >"$preflight_out" 2>"$preflight_err"; then
  if ! "$ward_binary" codex install --scope user; then
    if restore_installation_snapshot; then
      printf '%s\n' 'ward installer: Core configuration failed; the exact Core and binary snapshot was restored' >&2
    fi
    exit 1
  fi
  if "$ward_binary" doctor --project "$PWD" --json >/dev/null; then
    printf '%s\n' 'Ward Core configured. Hook definition trust is required and was not verified; confirm it once in Codex /hooks.'
  else
    if restore_installation_snapshot; then
      printf '%s\n' 'ward installer: Doctor reported an unhealthy check; the exact Core and binary snapshot was restored' >&2
    fi
    exit 1
  fi
else
  sed -n '1,20p' "$preflight_err" >&2
  restore_installation_snapshot
  printf '%s\n' 'ward installer: Core preflight failed; the exact Core and binary snapshot was restored' >&2
  exit 1
fi
