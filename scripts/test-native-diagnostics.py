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
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET


class CheckFailure(Exception):
    def __init__(self, code, **details):
        super().__init__(code)
        self.code = code
        self.details = details


STATUS_ERROR_CODES = {
    "ownership_conflict", "service_unavailable", "runtime_unavailable",
    "collector_unresponsive",
}


def project_collector_status(status, previous_generation):
    """Project recovery state without identities, dates, paths, or raw errors."""
    result = {"generation_changed": False}
    if not isinstance(status, dict):
        return result
    for field in ("enabled", "running", "ready"):
        if type(status.get(field)) is bool:
            result[field] = status[field]
    runtime = status.get("runtime")
    if isinstance(runtime, dict):
        if type(runtime.get("fresh")) is bool:
            result["runtime_fresh"] = runtime["fresh"]
        generation = runtime.get("generation")
        if (isinstance(generation, str) and re.fullmatch(r"[0-9a-f]{32}", generation)
                and isinstance(previous_generation, str)
                and re.fullmatch(r"[0-9a-f]{32}", previous_generation)):
            result["generation_changed"] = generation != previous_generation
    code = status.get("error_code")
    if isinstance(code, str) and code in STATUS_ERROR_CODES:
        result["error_code"] = code
    return result


def project_windows_task_state(task):
    """Only bounded Task Scheduler scalars may leave the captured COM reply."""
    result = {}
    if not isinstance(task, dict):
        return result
    if type(task.get("enabled")) is bool:
        result["enabled"] = task["enabled"]
    for field, lower, upper in (("state", 0, 4), ("last_result", -(1 << 31), (1 << 32) - 1),
                                ("running_instances", 0, 256)):
        value = task.get(field)
        if type(value) is int and lower <= value <= upper:
            result[field] = value
    return result


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
        elif b"diagnostics service backend failed" in result.stderr:
            code = "service_backend_failed"
        elif b"diagnostics service command failed" in result.stderr:
            code = "service_command_failed"
        elif b"diagnostics service response is invalid" in result.stderr:
            code = "service_response_invalid"
        details = {"command": label, "exit_code": result.returncode}
        if label == "ward diagnostics status --json" and len(result.stdout) <= 65536:
            try:
                status = json.loads(result.stdout)
            except (ValueError, UnicodeError):
                status = None
            if (isinstance(status, dict)
                    and status.get("schema") == "ward-diagnostics-status/v1"
                    and isinstance(status.get("error_code"), str)
                    and status.get("error_code") in STATUS_ERROR_CODES):
                details["status_error_code"] = status["error_code"]
        hresult = re.search(rb"diagnostics service backend failed \(hresult=0x([0-9a-f]{8})\)", result.stderr)
        if hresult:
            details["hresult"] = "0x" + hresult[1].decode("ascii")
        for phase in ("registration", "start"):
            if ("diagnostics service " + phase + " failed").encode() in result.stderr:
                details["phase"] = phase
                break
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


def project_task_xml(xml_text, *, expected_user_id=None, expected_command=None,
                     expected_arguments=None):
    """Bounded structural evidence; no dynamic values or raw XML escape."""
    require(len(xml_text) <= 65536 and "<!DOCTYPE" not in xml_text.upper()
            and "<!ENTITY" not in xml_text.upper(), "task_projection_xml_rejected")
    known = set("Task RegistrationInfo Description URI Author Date Version Source Documentation "
                "Triggers LogonTrigger RegistrationTrigger Enabled UserId Delay StartBoundary EndBoundary Repetition "
                "Interval Duration StopAtDurationEnd Principals Principal GroupId LogonType "
                "RunLevel DisplayName ProcessTokenSidType RequiredPrivileges Privilege Settings "
                "MultipleInstancesPolicy DisallowStartIfOnBatteries StopIfGoingOnBatteries "
                "AllowHardTerminate StartWhenAvailable RunOnlyIfNetworkAvailable IdleSettings "
                "WaitTimeout StopOnIdleEnd RestartOnIdle AllowStartOnDemand Hidden RunOnlyIfIdle "
                "WakeToRun ExecutionTimeLimit Priority RestartOnFailure Count NetworkSettings "
                "Id Name NetworkProfileName DeleteExpiredTaskAfter UseUnifiedSchedulingEngine "
                "DisallowStartOnRemoteAppSession Volatile MaintenanceSettings Period Deadline "
                "Exclusive Actions Exec Command Arguments WorkingDirectory".split())
    booleans = set("Enabled DisallowStartIfOnBatteries StopIfGoingOnBatteries AllowHardTerminate "
                   "StartWhenAvailable RunOnlyIfNetworkAvailable StopOnIdleEnd RestartOnIdle "
                   "AllowStartOnDemand Hidden RunOnlyIfIdle WakeToRun UseUnifiedSchedulingEngine "
                   "DisallowStartOnRemoteAppSession Volatile Exclusive".split())
    durations = {"Duration", "WaitTimeout", "ExecutionTimeLimit", "Interval", "DeleteExpiredTaskAfter"}
    namespace = "http://schemas.microsoft.com/windows/2004/02/mit/task"
    attribute_shapes = {
        "Task": {"version"},
        "Task/Principals/Principal": {"id"},
        "Task/Actions": {"Context"},
    }
    known_attributes = {"version", "id", "Context"}
    result = {"element_counts": {}, "settings": {}, "attribute_counts": {},
              "attribute_shape_matches": {}, "all_element_namespaces_match": True}
    root = ET.fromstring(xml_text)
    result["root_namespace_matches"] = root.tag == "{" + namespace + "}Task"
    nodes_by_path = {}
    visited = 0

    def visit(node, parents):
        nonlocal visited
        visited += 1
        require(visited <= 128 and len(parents) < 10, "task_projection_bounds_exceeded")
        local = node.tag.rsplit("}", 1)[-1]
        name = local if local in known else "Unknown"
        path = parents + [name]
        key = "/".join(path)
        nodes_by_path.setdefault(key, []).append(node)
        result["element_counts"][key] = result["element_counts"].get(key, 0) + 1
        result["all_element_namespaces_match"] &= node.tag.startswith("{" + namespace + "}")
        attributes = result["attribute_counts"].setdefault(key, {})
        for attribute in node.attrib:
            label = attribute if attribute in known_attributes else "Unknown"
            attributes[label] = attributes.get(label, 0) + 1
        result["attribute_shape_matches"].setdefault(key, []).append(
            set(node.attrib) == attribute_shapes.get(key, set())
        )
        if path[:2] == ["Task", "Settings"] and len(node) == 0:
            value = (node.text or "").strip()
            allowed = ((name in booleans and value in {"true", "false"})
                       or (name in durations and value in {"PT0S", "PT1M", "PT5M", "PT10M", "PT1H", "P3D"})
                       or (name == "MultipleInstancesPolicy" and value in {"Parallel", "Queue", "IgnoreNew", "StopExisting"})
                       or (name == "Priority" and value in {str(i) for i in range(11)})
                       or (name == "Count" and value in {"1", "2", "3"}))
            result["settings"].setdefault(key, []).append(value if allowed else "redacted")
        for child in node:
            visit(child, path)

    visit(root, [])
    text_expectations = {
        "principal_user_id": ("Task/Principals/Principal/UserId", expected_user_id),
        "logon_user_id": ("Task/Triggers/LogonTrigger/UserId", expected_user_id),
        "principal_logon_type": ("Task/Principals/Principal/LogonType", "InteractiveToken"),
        "registration_description": ("Task/RegistrationInfo/Description", "Ward local diagnostics collector"),
        "exec_command": ("Task/Actions/Exec/Command", expected_command),
        "exec_arguments": ("Task/Actions/Exec/Arguments", expected_arguments),
    }
    matches = {}
    for label, (path, expected) in text_expectations.items():
        if expected is None:
            continue
        nodes = nodes_by_path.get(path, [])
        matches[label] = (len(nodes) == 1 and len(nodes[0]) == 0
                          and nodes[0].tag.startswith("{" + namespace + "}")
                          and nodes[0].text == expected)
    for label, path, attribute, expected in (
            ("task_version", "Task", "version", "1.2"),
            ("principal_id", "Task/Principals/Principal", "id", "CurrentUser"),
            ("actions_context", "Task/Actions", "Context", "CurrentUser")):
        nodes = nodes_by_path.get(path, [])
        matches[label] = len(nodes) == 1 and nodes[0].attrib.get(attribute) == expected
    result["expected_value_matches"] = matches
    return result


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
        self.installation = self.bin_dir / ".ward-diagnostics/installation.json"
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
        self.user_id = None
        self.service_file = None
        self.service_attempted = False
        self.initial_absence = False
        self.owned_edit = None
        self.owned_fault_directory = None
        self.rows = []
        self.failure = None
        self.cleanup_ok = False
        self.initial_env = dict(self.env)
        self.drift_root = self.root / "environment-drift"
        self.locator_bytes = None

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

    def record_windows_task_projection(self):
        if self.platform != "win32" or self.native_id is None:
            return
        script = r"""$ErrorActionPreference='Stop'
$utf8=[Text.UTF8Encoding]::new($false)
[Console]::InputEncoding=$utf8; [Console]::OutputEncoding=$utf8
$request=[Console]::In.ReadToEnd()|ConvertFrom-Json
$scheduler=New-Object -ComObject 'Schedule.Service'; $scheduler.Connect()
$folder=$scheduler.GetFolder('\'); $task=$null
try { $task=$folder.GetTask($request.Name) } catch {
  if($_.Exception.GetBaseException().HResult -ne -2147024894){ throw }
}
if($null -eq $task){ '{"exists":false}' }else{
  @{exists=$true;xml=$task.Xml;enabled=[bool]$task.Enabled;state=[int]$task.State;last_result=[long]$task.LastTaskResult;running_instances=[int]$task.GetInstances(0).Count}|ConvertTo-Json -Compress
}
"""
        try:
            response = run([powershell_path(), "-NoLogo", "-NoProfile", "-NonInteractive",
                            "-Command", script], self.env, "fixture_task_projection",
                           payload=json.dumps({"Name": self.native_id}).encode(), timeout=15)
            require(len(response.stdout) <= 131072, "task_projection_reply_too_large")
            task = json.loads(response.stdout)
            require(isinstance(task, dict), "task_projection_reply_invalid")
            if task.get("exists") is False:
                self.record("windows_task_projection", available=True, task_exists=False)
                return
            require(task.get("exists") is True and isinstance(task.get("xml"), str),
                    "task_projection_reply_invalid")
            projection = project_task_xml(
                task["xml"], expected_user_id=self.user_id,
                expected_command=str(self.collector),
                expected_arguments=subprocess.list2cmdline([
                    "diagnostics", "serve", "--core-dir", str(self.core),
                    "--home-dir", str(self.home), "--binary-path", str(self.binary),
                ]),
            )
            self.record("windows_task_projection", available=True, task_exists=True,
                        dynamic_values_redacted=True,
                        scheduler_state=project_windows_task_state(task), **projection)
        except (CheckFailure, OSError, ValueError, ET.ParseError) as error:
            code = error.code if isinstance(error, CheckFailure) else type(error).__name__
            self.record("windows_task_projection", available=False, error_code=code)

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
        self.user_id = user_id
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

    def require_ready(self, status=None):
        if status is None:
            status = self.status()
        require(status["enabled"] and status["running"] and status["ready"], "collector_not_ready")
        require(status["runtime"]["fresh"], "heartbeat_not_fresh")
        require(status["runtime"]["write_errors"] == 0, "collector_storage_error")
        require(Path(status["log_dir"]) == self.logs, "unexpected_log_directory")
        return status

    def verify_installation(self):
        require(self.installation.is_file() and not self.installation.is_symlink()
                and not self.installation.parent.is_symlink(), "installation_locator_missing")
        raw = self.installation.read_bytes()
        require(len(raw) <= 16384, "installation_locator_too_large")
        locator = json.loads(raw)
        expected_home = Path(self.initial_env[
            "USERPROFILE" if self.platform == "win32" else "HOME"
        ]).resolve()
        require(isinstance(locator, dict)
                and set(locator) == {"schema", "binary_path", "core_dir", "home_dir"}
                and locator["schema"] == "ward-diagnostics-installation/v1",
                "installation_locator_schema_changed")
        require(Path(locator["binary_path"]) == self.binary
                and Path(locator["core_dir"]) == self.core
                and Path(locator["home_dir"]) == expected_home,
                "installation_locator_paths_changed")
        if self.platform != "win32":
            require(stat.S_IMODE(self.installation.stat().st_mode) == 0o600
                    and stat.S_IMODE(self.installation.parent.stat().st_mode) == 0o700,
                    "installation_locator_permissions_changed")
        owner = json.loads(self.manifest.read_bytes())
        require(owner.get("schema") == "ward-diagnostics-service-owner/v2",
                "installation_ownership_schema_changed")
        require(owner.get("installation_digest") == hashlib.sha256(raw).hexdigest(),
                "installation_ownership_binding_changed")
        self.locator_bytes = raw
        self.record("fixed_installation_locator", stored_paths_match=True,
                    ownership_schema_v2=True, ownership_digest_matches=True)

    def use_drifted_environment(self):
        overrides = {
            "HOME": self.drift_root / "home", "USERPROFILE": self.drift_root / "home",
            "CODEX_HOME": self.drift_root / "home/.codex",
            "XDG_STATE_HOME": self.drift_root / "state",
            "XDG_CONFIG_HOME": self.drift_root / "config",
            "LOCALAPPDATA": self.drift_root / "localappdata",
            "APPDATA": self.drift_root / "appdata",
        }
        for directory in overrides.values():
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.env.update({key: str(value) for key, value in overrides.items()})
        self.require_ready()
        require(not self.command_json("diagnostics", "enable")["changed"],
                "environment_drift_enable_not_noop")
        require(self.installation.read_bytes() == self.locator_bytes,
                "environment_drift_rewrote_locator")
        self.record("environment_drift_status_enable", stored_paths_used=True,
                    collector_ready=True, repeat_enable_no_op=True, locator_unchanged=True)

    def require_drifted_paths_unused(self):
        # OS caches may appear in LOCALAPPDATA; only Ward state and the exact
        # derived registration paths belong to this assertion.
        for path in (
                self.drift_root / "state/ward", self.drift_root / "localappdata/Ward",
                self.drift_root / "home/.local/state/ward",
                self.drift_root / "home/.codex/ward",
                self.drift_root / "config/systemd/user" / str(self.native_id),
                self.drift_root / "home/Library/LaunchAgents" / (str(self.native_id) + ".plist")):
            require(not path.exists() and not path.is_symlink(),
                    "environment_drift_created_ward_artifacts")

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
        # Include scheduling and process-start margin beyond the one-minute
        # Task Scheduler recovery interval.
        deadline = time.monotonic() + (180 if self.platform == "win32" else 25)
        last_status = {"generation_changed": False}
        last_failure = None
        recovery_codes = {
            "command_failed", "command_timeout", "command_unavailable",
            "invalid_management_json", "status_reply_too_large", "collector_not_ready",
            "heartbeat_not_fresh", "collector_storage_error", "unexpected_log_directory",
        }
        while time.monotonic() < deadline:
            last_failure = None
            try:
                response = self.cli("diagnostics", "status", "--json", expected=None)
                require(len(response.stdout) <= 65536, "status_reply_too_large")
                try:
                    status = json.loads(response.stdout)
                except (ValueError, UnicodeError):
                    raise CheckFailure("invalid_management_json") from None
                last_status = project_collector_status(status, before["generation"])
                require(isinstance(status, dict)
                        and status.get("schema") == "ward-diagnostics-status/v1"
                        and all(field in last_status for field in
                                ("enabled", "running", "ready", "runtime_fresh")),
                        "invalid_management_json")
                require(response.returncode == 0, "command_failed")
                self.require_ready(status)
                if last_status["generation_changed"]:
                    self.record("native_crash_restart", ready=True, generation_changed=True,
                                last_status=last_status)
                    return
            except CheckFailure as error:
                last_failure = (error.code if isinstance(error.code, str) and error.code in recovery_codes
                                else "unclassified_check_failure")
            time.sleep(0.5)
        raise CheckFailure("native_crash_restart_not_observed", last_status=last_status,
                           last_check_error_code=last_failure)

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

    def stop_windows_task_preserving_enabled(self, pid):
        """Stop only this verified collector, leaving its registration enabled."""
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                                     wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)  # query-limited + synchronize
        require(bool(handle), "windows_collector_process_unavailable")
        try:
            buffer = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(buffer))
            require(kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)),
                    "windows_collector_identity_unavailable")
            require(os.path.normcase(buffer.value) == os.path.normcase(str(self.collector)),
                    "windows_collector_identity_mismatch")
            script = r"""$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
$request=[Console]::In.ReadToEnd()|ConvertFrom-Json
$scheduler=New-Object -ComObject 'Schedule.Service'; $scheduler.Connect()
$task=$scheduler.GetFolder('\').GetTask($request.Name)
$definition=$task.Definition
$principal=$definition.Principal
$user=$principal.UserId
if($user -notmatch '^S-1-'){
 $user=([Security.Principal.NTAccount]::new($user)).Translate([Security.Principal.SecurityIdentifier]).Value
}
if(-not $task.Enabled -or $user -cne $request.UserID -or $principal.LogonType -ne 3 -or $principal.RunLevel -ne 0){throw 'fixture_identity_mismatch'}
if($definition.Actions.Count -ne 1){throw 'fixture_action_mismatch'}
$action=$definition.Actions.Item(1)
if($action.Type -ne 0 -or $action.Path -cne $request.Command -or $action.Arguments -cne $request.Arguments){throw 'fixture_action_mismatch'}
$task.Stop(0)
"""
            request = {
                "Name": self.native_id, "UserID": self.user_id, "Command": str(self.collector),
                "Arguments": subprocess.list2cmdline([
                    "diagnostics", "serve", "--core-dir", str(self.core),
                    "--home-dir", str(self.home), "--binary-path", str(self.binary),
                ]),
            }
            run([powershell_path(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                self.env, "stop_exact_fixture_task_preserving_enabled",
                payload=json.dumps(request).encode(), timeout=15)
            require(kernel.WaitForSingleObject(handle, 10000) == 0,
                    "windows_collector_stop_unconfirmed")
        finally:
            kernel.CloseHandle(handle)

    def remove_fault_directory(self):
        if self.owned_fault_directory is None:
            return
        path, original = self.owned_fault_directory
        current = path.lstat()
        require(stat.S_ISDIR(current.st_mode) and not path.is_symlink()
                and (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino),
                "fixture_fault_directory_changed_externally")
        path.rmdir()  # Only this exact owned directory, and only while empty.
        self.owned_fault_directory = None

    def restore_stopped_windows_service(self):
        if self.platform != "win32":
            return
        before = self.require_ready()["runtime"]  # Includes strict service ownership and authenticated Probe.
        self.stop_windows_task_preserving_enabled(before["pid"])
        stopped = self.status()
        require(stopped["enabled"] and not stopped["running"] and not stopped["ready"],
                "windows_enabled_stopped_fixture_unconfirmed")
        saved = {path.name: path.read_bytes() for path in self.logs.glob("events-*.jsonl")}
        require(bool(saved), "rollback_fixture_has_no_prior_log")
        # A valid segment name with the wrong file type fails startup pruning
        # before a runtime descriptor is published. No production fault flags.
        suffix = hashlib.sha256(str(self.root).encode()).hexdigest()[:32]
        fault = self.logs / ("events-20000101T000000.000000000Z-" + suffix + "-000001.jsonl")
        fault.mkdir(mode=0o700)
        self.owned_fault_directory = (fault, fault.lstat())
        result = self.cli("diagnostics", "enable", expected=None)
        evidence = {
            "exit_code": result.returncode,
            "saw_previous_state_restored": b"previous state restored" in result.stderr,
            "saw_readiness_failure": b"collector readiness failed" in result.stderr,
            "saw_rollback_failure": b"rollback failed" in result.stderr,
        }
        self.record("windows_stopped_restore_enable_result", **evidence)
        require(result.returncode != 0 and evidence["saw_previous_state_restored"]
                and evidence["saw_readiness_failure"] and not evidence["saw_rollback_failure"],
                "windows_stopped_restore_rollback_not_confirmed")
        restored = self.status()
        self.record("windows_stopped_restore_immediate_state",
                    **project_collector_status(restored, before["generation"]))
        require(restored["enabled"] and not restored["running"] and not restored["ready"],
                "windows_stopped_restore_started_immediately")
        require(not (self.control / "runtime.json").exists(),
                "windows_failed_collector_published_runtime")
        self.remove_fault_directory()
        self.record("windows_enabled_stopped_rollback", previous_state_restored=True,
                    immediate_enabled=True, immediate_running=False,
                    startup_fault_removed=True)
        deadline = time.monotonic() + 180
        last_status = {"generation_changed": False}
        while time.monotonic() < deadline:
            # status performs the production authenticated readiness probe.
            status = self.status()
            last_status = project_collector_status(status, before["generation"])
            if status["enabled"] and status["running"] and status["ready"]:
                self.require_ready(status)
                require(last_status["generation_changed"], "windows_restored_generation_unchanged")
                require(all((self.logs / name).read_bytes() == data for name, data in saved.items()),
                        "windows_stopped_restore_changed_existing_logs")
                self.record("windows_stopped_restore_delayed_recovery", ready=True,
                            generation_changed=True, existing_logs_preserved=True,
                            last_status=last_status)
                return
            time.sleep(0.5)
        raise CheckFailure("windows_stopped_restore_recovery_not_observed", last_status=last_status)

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
        for path in (self.collector, self.manifest, self.installation, self.control / "runtime.json",
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
        self.record("native_enable_return", exit_code=0, enabled=enabled.get("enabled"),
                    changed=enabled.get("changed"))
        status = self.require_ready()
        require(enabled["enabled"] and enabled["changed"], "enable_result_invalid")
        require(Path(enabled["collector_binary"]) == self.collector, "unexpected_collector_path")
        self.record("native_enable", backend=status["backend"], ready=True, heartbeat_fresh=True)
        self.verify_installation()
        require(not self.command_json("diagnostics", "enable")["changed"], "repeat_enable_not_noop")
        self.record("repeat_enable", no_op=True)
        self.use_drifted_environment()
        self.synthetic_hook()
        self.restore_stopped_windows_service()
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
        self.require_drifted_paths_unused()
        self.record("environment_drift_disable", original_service_removed=True,
                    locator_removed=True, alternate_ward_paths_absent=True)
        self.env = dict(self.initial_env)
        self.command_json("diagnostics", "enable")
        self.require_ready()
        self.disable_and_check()
        self.record("second_enable_disable_cycle", passed=True)

    def cleanup(self):
        try:
            self.restore_edit()
            self.remove_fault_directory()
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
        smoke.record_windows_task_projection()
    finally:
        if smoke is not None:
            smoke.cleanup()
    return smoke.report()


if __name__ == "__main__":
    sys.exit(main())
