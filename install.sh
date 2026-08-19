#!/bin/sh
set -eu

repo="jgoneit/ward"
version=""
codex_dir=${CODEX_HOME:-"$HOME/.codex"}
install_dir=${WARD_INSTALL_DIR:-"$codex_dir/ward/bin"}

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
candidate="$install_dir/.ward.new.$$"
cp "$tmp_dir/ward" "$candidate"
chmod 0755 "$candidate"
mv -f "$candidate" "$install_dir/ward"
printf 'installed Ward %s at %s\n' "$version" "$install_dir/ward"
printf 'run: %s codex install --scope user --profile baseline --dry-run\n' "$install_dir/ward"
