#!/bin/sh
set -eu

codex_dir=${CODEX_HOME:-"$HOME/.codex"}
install_dir=${WARD_INSTALL_DIR:-"$codex_dir/ward/bin"}
codex_dir=${codex_dir%/}
install_dir=${install_dir%/}
binary="$install_dir/ward"
hooks_file="$codex_dir/hooks.json"
config_file="$codex_dir/config.toml"

case "$codex_dir" in
  /*) ;;
  *) printf '%s\n' 'Ward uninstaller: CODEX_HOME must be absolute' >&2; exit 2 ;;
esac
case "/$codex_dir/$install_dir/" in
  *"/../"*|*"/./"*) printf '%s\n' 'Ward uninstaller: control paths must not contain dot traversal components' >&2; exit 2 ;;
esac
[ "$(dirname -- "$codex_dir")" = "$HOME" ] || {
  printf '%s\n' 'Ward uninstaller: v0.1 requires CODEX_HOME directly below HOME' >&2
  exit 2
}
case "$install_dir" in
  "$codex_dir"/*) ;;
  *) printf '%s\n' 'Ward uninstaller: WARD_INSTALL_DIR must remain below CODEX_HOME' >&2; exit 2 ;;
esac
control_cursor=$install_dir
while :; do
  if [ -L "$control_cursor" ]; then
    printf 'Ward uninstaller: control path must not contain a symbolic link: %s\n' "$control_cursor" >&2
    exit 2
  fi
  [ "$control_cursor" != "$codex_dir" ] || break
  control_parent=$(dirname -- "$control_cursor")
  [ "$control_parent" != "$control_cursor" ] || {
    printf '%s\n' 'Ward uninstaller: could not validate the CODEX_HOME control chain' >&2
    exit 2
  }
  control_cursor=$control_parent
done

if [ -e "$binary" ] || [ -L "$binary" ]; then
	if [ -L "$binary" ] || [ ! -f "$binary" ]; then
		printf 'Ward uninstaller: refusing non-regular binary at %s; restore the exact Ward binary, then retry\n' "$binary" >&2
		exit 1
	fi
	if [ ! -x "$binary" ]; then
		printf 'Ward uninstaller: binary at %s is not executable; restore its execute bit or reinstall the same version, then retry\n' "$binary" >&2
		exit 1
	fi
	"$binary" codex uninstall --scope user
  rm -f "$binary"
  printf 'removed %s\n' "$binary"
else
	ward_refs=0
	if [ -e "$hooks_file" ] && [ ! -f "$hooks_file" ]; then
		ward_refs=1
	elif [ -f "$hooks_file" ]; then
		if LC_ALL=C grep -Fq "$binary" "$hooks_file" || LC_ALL=C grep -Eq 'hook codex-(session-start|pre-tool-use|permission-request|post-tool-use)' "$hooks_file"; then
			ward_refs=1
		fi
	fi
	if [ -e "$config_file" ] && [ ! -f "$config_file" ]; then
		ward_refs=1
	elif [ -f "$config_file" ] && LC_ALL=C grep -Eq '# >>> ward (default permissions|permission profile) v3 >>>|# ward:migrated-sandbox-mode:v3|default_permissions[[:space:]]*=[[:space:]]*"ward"|\[permissions\.ward\]' "$config_file"; then
		ward_refs=1
	fi
	if [ "$ward_refs" -eq 1 ]; then
		printf 'Ward uninstaller: binary is missing at %s while Ward hook or config references remain; reinstall the same version, then retry\n' "$binary" >&2
		exit 1
	fi
	printf '%s\n' 'Ward integration is already absent; no Ward hook or config references were found.'
fi

printf '%s\n' 'Ward state directory was preserved.'
