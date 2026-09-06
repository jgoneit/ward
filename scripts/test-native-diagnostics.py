#!/usr/bin/env python3
"""Exercise real per-user diagnostics services in an isolated fixture.

This opt-in test requires a native logged-in user/service manager. It does not
start systemd, enable linger, elevate privileges, or configure a Codex Host.
The direct Hook replay below is synthetic and is not Host dispatch evidence.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time


class CheckFailure(Exception):
    def __init__(self, code, **details):
        super().__init__(code)
        self.code = code
        self.details = details


def require(condition, code):
    if not condition:
        raise CheckFailure(code)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(argv, env, label, *, payload=None, timeout=45, expected=0):
    try:
        result = subprocess.run(
            [str(arg) for arg in argv], env=env, input=payload,
            capture_output=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise CheckFailure("command_timeout", command=label) from None
    except OSError as error:
        raise CheckFailure("command_unavailable", command=label, errno=error.errno) from None
    if expected is not None and result.returncode != expected:
        code = "command_failed"
        # Only classify Ward's static management errors; never report raw output.
        if b"diagnostics user service is unavailable" in result.stderr:
            code = "unsupported_user_service_environment"
        elif b"ownership conflict" in result.stderr:
            code = "ownership_conflict"
        elif b"diagnostics_owner_mismatch" in result.stderr:
            code = "diagnostics_owner_mismatch"
        elif b"diagnostics collector readiness failed" in result.stderr:
            code = "collector_readiness_failed"
        elif b"diagnostics collector stop is unconfirmed" in result.stderr:
            code = "collector_stop_unconfirmed"
        details = {"command": label, "exit_code": result.returncode}
        for phrase, outcome in (
                (b"rollback failed", "failed"),
                (b"previous state restored", "previous_state_restored"),
                (b"newly created artifacts removed", "new_artifacts_removed")):
            if phrase in result.stderr:
                details["rollback"] = outcome
                break
        raise CheckFailure(code, **details)
    return result


def powershell_path():
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    kernel.GetSystemDirectoryW.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel.GetSystemDirectoryW(buffer, len(buffer))
    require(0 < length < len(buffer), "windows_system_directory_unavailable")
    return str(Path(buffer.value) / "WindowsPowerShell/v1.0/powershell.exe")


def normalize_linux_bus(env):
    """Fill missing values only from an existing current-user runtime socket."""
    runtime = Path(env.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}")
    if not runtime.is_absolute():
        return
    try:
        directory = runtime.lstat()
        bus = (runtime / "bus").lstat()
    except OSError:
        return
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid()
            or directory.st_mode & 0o022 or not stat.S_ISSOCK(bus.st_mode)
            or bus.st_uid != os.getuid()):
        return
    env.setdefault("XDG_RUNTIME_DIR", str(runtime))
    env.setdefault("DBUS_SESSION_BUS_ADDRESS", "unix:path=" + str(runtime / "bus"))


class NativeSmoke:
    def __init__(self, args):
        self.args = args
        self.platform = sys.platform
        require(self.platform in ("darwin", "linux", "win32"), "unsupported_os")
        self.env = dict(os.environ)
        self.root = Path(tempfile.mkdtemp(prefix="ward-native-diagnostics-")).resolve()
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir(mode=0o700)
        suffix = ".exe" if self.platform == "win32" else ""
        self.binary = self.bin_dir / ("ward" + suffix)
        self.collector = self.bin_dir / ("ward-diagnostics" + suffix)
        shutil.copyfile(args.candidate, self.binary)
        self.binary.chmod(0o700)
        # No command ever reads or updates the real Codex configuration.
        self.env["CODEX_HOME"] = str(self.root / "codex")
        if self.platform == "win32":
            self.env["USERPROFILE"] = str(self.home)
            self.env["LOCALAPPDATA"] = str(self.root / "localappdata")
            self.core = self.root / "localappdata/Ward/state/core"
        else:
            self.env["XDG_STATE_HOME"] = str(self.root / "state")
            self.core = self.root / "state/ward/core"
            if self.platform == "darwin":
                self.env["HOME"] = str(self.home)
                self.env.pop("XDG_CONFIG_HOME", None)
            else:
                # The existing user manager must search the actual unit dir.
                # Changing HOME/XDG_CONFIG_HOME here would invalidate that test.
                normalize_linux_bus(self.env)
        self.control = self.core / "diagnostics"
        self.logs = self.core.parent / "diagnostics"
        self.manifest = self.control / "service-owner.json"
        self.native_id = None
        self.service_file = None
        self.service_attempted = False
        self.initial_absence = False
        self.owned_edit = None
        self.rows = []
        self.failure = None
        self.cleanup_ok = False

    def record(self, step, **details):
        row = {"step": step, **details}
        self.rows.append(row)
        print(json.dumps(row, sort_keys=True), flush=True)

    def cli(self, *args, expected=0):
        return run([self.binary, *args], self.env, "ward " + " ".join(args), expected=expected)

    def command_json(self, *args):
        result = self.cli(*args)
        try:
            return json.loads(result.stdout)
        except (ValueError, UnicodeError):
            raise CheckFailure("invalid_management_json") from None

    def status(self):
        return self.command_json("diagnostics", "status", "--json")

    def identify_service(self):
        if self.platform == "win32":
            result = run(
                [powershell_path(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                 "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
                self.env, "current_windows_sid", timeout=15,
            )
            user_id = result.stdout.decode("utf-8-sig").strip()
            require(user_id.startswith("S-1-"), "invalid_current_windows_sid")
        else:
            user_id = str(os.getuid())
        value = hashlib.sha256((user_id + "\0" + str(self.binary)).encode()).hexdigest()[:24]
        if self.platform == "darwin":
            self.native_id = "io.github.jgoneit.ward.diagnostics." + value
            self.service_file = self.home / "Library/LaunchAgents" / (self.native_id + ".plist")
        elif self.platform == "linux":
            self.native_id = "ward-diagnostics-" + value + ".service"
            home = Path(self.env.get("HOME", ""))
            require(home.is_absolute(), "linux_home_unavailable")
            config = Path(self.env.get("XDG_CONFIG_HOME") or home / ".config")
            require(config.is_absolute(), "linux_config_home_not_absolute")
            self.service_file = config / "systemd/user" / self.native_id
        else:
            self.native_id = "WardDiagnostics-" + value

    def require_native_absent(self):
        if self.service_file is not None:
            require(not self.service_file.exists() and not self.service_file.is_symlink(),
                    "native_service_file_remains")
        if self.platform == "darwin":
            result = run(
                ["/bin/launchctl", "print", f"gui/{os.getuid()}/{self.native_id}"],
                self.env, "launchd_exact_service_absence", timeout=10, expected=None,
            )
            require(result.returncode == 113, "launchd_absence_unconfirmed")
        elif self.platform == "linux":
            result = run(
                ["systemctl", "--user", "show", self.native_id,
                 "--property=LoadState", "--value", "--no-pager"],
                self.env, "systemd_exact_service_absence", timeout=10, expected=None,
            )
            require(result.stdout.strip() == b"not-found", "systemd_absence_unconfirmed")
        else:
            # Ward queries precisely this task through COM even with no files.
            status = self.status()
            require(not status["enabled"] and not status["running"], "windows_task_remains")

    def assert_fixture_unchanged(self, before):
        after = self.fixture_snapshot()
        if after != before:
            # Relative fixture names only; no contents or runtime credentials.
            raise CheckFailure("dry_run_created_or_changed_artifacts",
                               added=sorted(after.keys() - before.keys()),
                               removed=sorted(before.keys() - after.keys()),
                               changed=sorted(key for key in before.keys() & after.keys()
                                              if before[key] != after[key]))
        self.require_native_absent()

    def fixture_snapshot(self):
        # Called before activation only: no runtime descriptor/key is read.
        # Windows PowerShell may maintain its own LOCALAPPDATA caches even
        # during read-only COM queries. Inspect every Ward/Codex fixture path;
        # native registration absence is checked separately on all platforms.
        snapshot = {}
        for root in (self.bin_dir, self.core.parent, self.root / "codex"):
            if root.exists():
                for path in (root, *root.rglob("*")):
                    snapshot[str(path.relative_to(self.root))] = (
                        "dir" if path.is_dir() else digest(path)
                    )
        return snapshot

    def require_ready(self):
        status = self.status()
        require(status["enabled"] and status["running"] and status["ready"], "collector_not_ready")
        require(status["runtime"]["fresh"], "heartbeat_not_fresh")
        require(status["runtime"]["write_errors"] == 0, "collector_storage_error")
        require(Path(status["log_dir"]) == self.logs, "unexpected_log_directory")
        return status

    def synthetic_hook(self):
        marker = "native-service-smoke-call"
        canary = "ward-native-sensitive-canary"
        payload = json.dumps({
            "hook_event_name": "PreToolUse", "session_id": "native-smoke-session",
            "turn_id": "native-smoke-turn", "tool_use_id": marker,
            "cwd": str(self.root), "tool_name": "Bash",
            "tool_input": {"command": "printf " + canary},
        }).encode()
        result = run([self.binary, "hook", "codex-pre-tool-use"], self.env,
                     "synthetic_direct_hook", payload=payload, timeout=3)
        require(not result.stdout and not result.stderr, "synthetic_hook_policy_output_changed")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            found = False
            for path in self.logs.glob("events-*.jsonl"):
                data = path.read_bytes()
                require(canary.encode() not in data and str(self.root).encode() not in data,
                        "sensitive_canary_reached_log")
                for line in data.splitlines():
                    event = json.loads(line)["event"]
                    if event["tool_use_id"] == marker:
                        require(event["outcome"] == "defer", "synthetic_hook_outcome_changed")
                        found = True
            if found:
                self.record("synthetic_direct_hook_replay", recorded=True,
                            stdout_empty=True, stderr_empty=True, exit_code=0,
                            actual_host_dispatch=False, sensitive_canary_absent=True)
                return
            time.sleep(0.1)
        raise CheckFailure("synthetic_hook_event_not_received")

    def crash_collector(self):
        before = self.require_ready()["runtime"]
        if self.platform == "darwin":
            run(["/bin/launchctl", "kill", "SIGKILL", f"gui/{os.getuid()}/{self.native_id}"],
                self.env, "crash_fixture_launchd_collector", timeout=10)
        elif self.platform == "linux":
            run(["systemctl", "--user", "kill", "--kill-whom=main", "--signal=KILL", self.native_id],
                self.env, "crash_fixture_systemd_collector", timeout=10)
        else:
            self.crash_windows_process(before["pid"])
        # Task Scheduler advertises a one-minute failure restart interval.
        deadline = time.monotonic() + (105 if self.platform == "win32" else 25)
        while time.monotonic() < deadline:
            try:
                after = self.require_ready()["runtime"]
                if after["generation"] != before["generation"]:
                    self.record("native_crash_restart", ready=True, generation_changed=True)
                    return
            except CheckFailure:
                pass
            time.sleep(0.5)
        raise CheckFailure("native_crash_restart_not_observed")

    def crash_windows_process(self, pid):
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                                     wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateProcess.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x1000 | 0x0001, False, pid)  # query-limited + terminate
        require(bool(handle), "windows_collector_process_unavailable")
        try:
            buffer = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(buffer))
            require(kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)),
                    "windows_collector_identity_unavailable")
            require(os.path.normcase(buffer.value) == os.path.normcase(str(self.collector)),
                    "windows_collector_identity_mismatch")
            # Terminate this verified handle with a failure code; do not End the
            # task, which would test an intentional stop rather than recovery.
            require(kernel.TerminateProcess(handle, 1), "windows_collector_crash_failed")
        finally:
            kernel.CloseHandle(handle)

    def ownership_conflicts(self):
        original = self.manifest.read_bytes()
        value = json.loads(original)
        value["collector_digest"] = "0" * 64
        modified = json.dumps(value).encode()
        self.owned_edit = (self.manifest, original, modified)
        self.manifest.write_bytes(modified)
        result = self.cli("diagnostics", "enable", expected=None)
        require(result.returncode != 0 and b"ownership conflict" in result.stderr,
                "modified_manifest_not_rejected")
        require(self.manifest.read_bytes() == modified, "modified_manifest_overwritten")
        self.restore_edit()
        self.require_ready()
        self.record("modified_ownership_manifest", rejected=True, preserved=True, collector_ready=True)

    def restore_edit(self):
        if self.owned_edit is None:
            return
        path, original, modified = self.owned_edit
        require(path.read_bytes() == modified, "fixture_edit_changed_externally")
        path.write_bytes(original)
        self.owned_edit = None

    def refresh_binary(self):
        if self.args.updated_candidate is None:
            self.record("same_version_binary_refresh", performed=False,
                        reason="updated_candidate_not_supplied")
            return
        old_digest = digest(self.binary)
        old_version = self.cli("--version").stdout
        updated_version = run([self.args.updated_candidate, "--version"], self.env,
                              "updated_candidate_version", timeout=10).stdout
        require(old_version == updated_version, "candidate_versions_differ")
        require(old_digest != digest(self.args.updated_candidate), "candidate_digests_identical")
        # The original Ward executable must be replaceable while its separate
        # collector copy runs, including on Windows.
        shutil.copyfile(self.args.updated_candidate, self.binary)
        self.binary.chmod(0o700)
        require(self.require_ready()["update_available"], "digest_update_not_detected")
        result = self.command_json("diagnostics", "enable")
        require(result["changed"], "collector_copy_not_refreshed")
        require(not self.require_ready()["update_available"], "collector_update_still_pending")
        require(digest(self.collector) == digest(self.binary), "collector_digest_mismatch")
        self.record("same_version_binary_refresh", performed=True, sha256_changed=True,
                    same_version=True, copy_matches=True, ready=True)

    def disable_and_check(self):
        saved = {path.name: path.read_bytes() for path in self.logs.glob("events-*.jsonl")}
        result = self.command_json("diagnostics", "disable")
        require(not result["enabled"], "disable_left_enabled")
        status = self.status()
        require(not status["enabled"] and not status["running"], "disable_left_running")
        for path in (self.collector, self.manifest, self.control / "runtime.json",
                     self.control / "heartbeat.json"):
            require(not path.exists(), "disable_left_owned_artifact")
        self.require_native_absent()
        require(all((self.logs / name).read_bytes() == data for name, data in saved.items()),
                "disable_changed_existing_logs")
        return result

    def exercise(self):
        self.identify_service()
        # Cold Windows PowerShell initializes module/runtime caches in its
        # isolated profile. Warm the same COM inspection before the snapshot;
        # the dry-run claim concerns Ward-owned artifacts, not OS first use.
        initial = self.status()
        require(not initial["enabled"] and not initial["running"], "initial_status_not_disabled")
        snapshot = self.fixture_snapshot()
        # Let Ward's real preflight classify unsupported environments before
        # interpreting an unavailable manager as a missing registration.
        dry = self.command_json("diagnostics", "enable", "--dry-run")
        require(dry["changed"] and dry["dry_run"], "enable_dry_run_result_invalid")
        self.require_native_absent()
        self.initial_absence = True
        self.assert_fixture_unchanged(snapshot)
        dry = self.command_json("diagnostics", "disable", "--dry-run")
        require(not dry["changed"] and dry["dry_run"], "disabled_dry_run_not_noop")
        self.assert_fixture_unchanged(snapshot)
        self.record("native_preflight_and_dry_run", supported=True, no_artifacts=True,
                    service_id=self.native_id)

        marker = b"owned-native-smoke-foreign-copy\n"
        self.collector.write_bytes(marker)
        self.collector.chmod(0o700)
        try:
            result = self.cli("diagnostics", "enable", expected=None)
            require(result.returncode != 0 and b"ownership conflict" in result.stderr,
                    "foreign_collector_not_rejected")
            require(self.collector.read_bytes() == marker, "foreign_collector_overwritten")
        finally:
            # Remove only the exact marker created by this test.
            if self.collector.exists() and self.collector.read_bytes() == marker:
                self.collector.unlink()
        self.assert_fixture_unchanged(snapshot)
        self.record("foreign_collector_conflict", rejected=True, preserved=True)

        self.service_attempted = True
        enabled = self.command_json("diagnostics", "enable")
        status = self.require_ready()
        require(enabled["enabled"] and enabled["changed"], "enable_result_invalid")
        require(Path(enabled["collector_binary"]) == self.collector, "unexpected_collector_path")
        self.record("native_enable", backend=status["backend"], ready=True, heartbeat_fresh=True)
        require(not self.command_json("diagnostics", "enable")["changed"], "repeat_enable_not_noop")
        self.record("repeat_enable", no_op=True)
        self.synthetic_hook()
        self.crash_collector()
        self.ownership_conflicts()
        self.refresh_binary()
        dry = self.command_json("diagnostics", "disable", "--dry-run")
        require(dry["changed"] and dry["dry_run"], "disable_dry_run_result_invalid")
        self.require_ready()
        self.record("disable_dry_run", collector_still_ready=True)
        require(self.disable_and_check()["changed"], "disable_not_changed")
        require(not self.command_json("diagnostics", "disable")["changed"], "repeat_disable_not_noop")
        self.record("native_disable", stopped=True, registration_removed=True,
                    artifacts_removed=True, logs_preserved=True, repeat_no_op=True)
        self.command_json("diagnostics", "enable")
        self.require_ready()
        self.disable_and_check()
        self.record("second_enable_disable_cycle", passed=True)

    def cleanup(self):
        try:
            self.restore_edit()
            if self.service_attempted:
                # Ward checks ownership and confirms the collector lock after
                # stopping. On failure preserve the live binary and fixture.
                self.disable_and_check()
            elif self.initial_absence:
                self.require_native_absent()
            shutil.rmtree(self.root)
            self.cleanup_ok = True
            self.record("cleanup", removed_fixture=True, service_absent=True)
        except (CheckFailure, OSError, ValueError) as error:
            code = error.code if isinstance(error, CheckFailure) else type(error).__name__
            self.record("cleanup", removed_fixture=False, service_absent_unconfirmed=True,
                        error_code=code, retained_fixture=str(self.root))

    def report(self):
        passed = self.failure is None and self.cleanup_ok
        report = {
            "schema": "ward-native-diagnostics-smoke/v1", "platform": self.platform,
            "passed": passed, "checks": self.rows,
            "candidate_sha256": digest(self.args.candidate),
            "not_proven": ["actual_codex_host_hook_dispatch", "logout_login_restart",
                           "real_user_global_activation"],
        }
        if self.args.updated_candidate is None:
            report["not_proven"].append("same_version_binary_refresh")
        if self.failure is not None:
            report["failure"] = self.failure
        if not self.cleanup_ok:
            report["retained_fixture"] = str(self.root)
        if self.args.report:
            self.args.report.parent.mkdir(parents=True, exist_ok=True)
            self.args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"passed": passed, "report": str(self.args.report) if self.args.report else None}),
              flush=True)
        return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--updated-candidate", type=Path,
                        help="same-version native binary with a different SHA-256")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    for name in ("candidate", "updated_candidate"):
        value = getattr(args, name)
        if value is not None:
            value = value.resolve()
            if not value.is_file():
                parser.error(name.replace("_", "-") + " must name a built native binary")
            setattr(args, name, value)
    if args.report:
        args.report = args.report.resolve()
    smoke = None
    try:
        smoke = NativeSmoke(args)
        smoke.exercise()
    except (CheckFailure, OSError, ValueError, KeyboardInterrupt) as error:
        failure = ({"code": error.code, **error.details} if isinstance(error, CheckFailure)
                   else {"code": type(error).__name__})
        if smoke is None:
            report = {"schema": "ward-native-diagnostics-smoke/v1", "platform": sys.platform,
                      "passed": False, "failure": failure, "checks": []}
            if args.report:
                args.report.parent.mkdir(parents=True, exist_ok=True)
                args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(report), flush=True)
            return 1
        smoke.failure = failure
        smoke.record("failure", **failure)
    finally:
        if smoke is not None:
            smoke.cleanup()
    return smoke.report()


if __name__ == "__main__":
    sys.exit(main())
