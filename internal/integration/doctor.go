package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/jgoneit/ward/internal/audit"
)

const doctorSchemaV1 = "ward-doctor/v1"

// Doctor performs read-only checks against the explicit integration paths.
// Warnings identify limitations that do not make the installed boundary
// internally inconsistent; any failed check sets Healthy to false.
func Doctor(options Options) DoctorReport {
	report := DoctorReport{Schema: doctorSchemaV1, Healthy: true}
	add := func(id string, status CheckStatus, message string) {
		report.Checks = append(report.Checks, Check{ID: id, Status: status, Message: message})
		if status == CheckFail {
			report.Healthy = false
		}
	}

	if err := validateOptions(options); err != nil {
		add("paths", CheckFail, err.Error())
		return report
	}
	add("paths", CheckPass, "Integration paths are explicit and absolute.")
	if !addControlPlaneChecks(&report, options.Paths) {
		return report
	}

	journalRaw, journalExists, err := readOptional(options.Paths.journalFile())
	if err != nil {
		add("journal", CheckFail, err.Error())
		return report
	}
	if !journalExists {
		add("journal", CheckFail, "Ward integration journal is missing.")
		return report
	}
	journal, err := decodeJournal(journalRaw)
	if err != nil {
		add("journal", CheckFail, err.Error())
		return report
	}
	if journal.ProfileName != options.profileName() {
		add("journal", CheckFail, "Journal profile does not match the requested profile.")
	} else if filepath.Clean(journal.BinaryPath) != filepath.Clean(options.Paths.BinaryPath) {
		add("journal", CheckFail, "Journal binary path does not match the running Ward binary.")
	} else {
		add("journal", CheckPass, "Ward integration journal is valid.")
	}
	checkPrivateFile(&report, "journal.permissions", options.Paths.journalFile())

	if info, err := os.Stat(options.Paths.BinaryPath); err != nil || !info.Mode().IsRegular() {
		add("binary", CheckFail, "Configured Ward binary is missing or not a regular file.")
	} else if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		add("binary", CheckFail, "Configured Ward binary is not executable.")
	} else {
		add("binary", CheckPass, "Configured Ward binary is present.")
	}

	hooksRaw, hooksExists, err := readOptional(options.Paths.HooksFile)
	if err != nil || !hooksExists {
		if err != nil {
			add("hooks", CheckFail, err.Error())
		} else {
			add("hooks", CheckFail, "Codex hooks.json is missing.")
		}
	} else {
		checkHooks(&report, hooksRaw, journal.BinaryPath)
		if journal.HooksDigest != "" && journal.HooksDigest != digest(hooksRaw) {
			add("hooks.changed", CheckWarn, "hooks.json changed after Ward installation; exact Ward handlers were checked separately.")
		}
	}

	configRaw, configExists, err := readOptional(options.Paths.ConfigFile)
	if err != nil || !configExists {
		if err != nil {
			add("permissions", CheckFail, err.Error())
		} else {
			add("permissions", CheckFail, "Codex config.toml is missing.")
		}
	} else {
		checkConfig(&report, configRaw, journal, options)
		if journal.ConfigDigest != "" && journal.ConfigDigest != digest(configRaw) {
			add("permissions.changed", CheckWarn, "config.toml changed after Ward installation; managed blocks were checked separately.")
		}
	}

	if info, err := os.Lstat(options.Paths.StateDir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		add("state", CheckFail, "Ward state directory is missing or not a directory.")
	} else if err := audit.InspectPrivateDirectory(options.Paths.StateDir); err != nil {
		add("state.permissions", CheckFail, "Ward state directory permissions are not private.")
	} else {
		add("state.permissions", CheckPass, "Ward state directory permissions are private.")
	}

	add("permissions.glob_depth", CheckWarn, "glob_scan_max_depth=4 bounds Linux, WSL, and Windows pre-expansion; secrets nested more deeply require explicit depth rules or a larger reviewed limit.")
	add("permissions.env_custom", CheckWarn, "Codex deny globs cannot be reopened by exact public-template rules; native policy denies .env and reviewed common suffixes, while other .env.<custom> names depend on observed Ward hooks.")
	add("permissions.credential_broker", CheckWarn, "Native credential-store and SSH-key denies can block subprocesses that read credentials directly; workflows without an OS keychain, ssh-agent, or equivalent broker require burn-in and are not yet claimed as normal-workflow compatible.")
	add("permissions.layers", CheckWarn, "This doctor checks the selected user config only; sandbox_mode in another loaded Codex layer can still override permission profiles.")
	add("hooks.managed", CheckWarn, "User config cannot prove that managed allow_managed_hooks_only policy permits this user-global hook.")
	add("hooks.trust", CheckWarn, "File inspection cannot prove Codex hook trust; review and trust the exact user hook definition in Codex.")
	return report
}

func checkHooks(report *DoctorReport, raw []byte, binaryPath string) {
	add := reportAdder(report)
	root, err := decodeJSONObject(raw)
	if err != nil {
		add("hooks", CheckFail, "hooks.json is not valid JSON: "+err.Error())
		return
	}
	var hooks map[string]json.RawMessage
	if err := json.Unmarshal(root["hooks"], &hooks); err != nil || hooks == nil {
		add("hooks", CheckFail, "hooks.json does not contain a hooks object.")
		return
	}
	allPass := true
	for _, spec := range wardHookSpecs {
		groups, err := decodeGroups(hooks[spec.Event])
		if err != nil {
			add("hooks."+spec.Event, CheckFail, err.Error())
			allPass = false
			continue
		}
		count, conflict := countWardHandlers(groups, spec.StatusMessage, hookCommand(binaryPath, spec.Subcommand))
		if conflict || count != 1 {
			add("hooks."+spec.Event, CheckFail, fmt.Sprintf("Expected exactly one unmodified Ward handler; found %d.", count))
			allPass = false
			continue
		}
		add("hooks."+spec.Event, CheckPass, "Ward handler is installed once with matcher * and a bounded synchronous timeout.")
	}
	if allPass {
		add("hooks", CheckPass, "All Ward Codex hook handlers are installed.")
	}
}

func checkConfig(report *DoctorReport, raw []byte, journal integrationJournal, options Options) {
	add := reportAdder(report)
	if err := validateTOML(raw); err != nil {
		add("permissions.syntax", CheckFail, "config.toml is not valid TOML.")
	} else {
		add("permissions.syntax", CheckPass, "config.toml is valid TOML.")
	}
	if hooksExplicitlyDisabled(raw) {
		add("hooks.feature", CheckFail, "Codex hooks are explicitly disabled in config.toml.")
	} else {
		add("hooks.feature", CheckPass, "Codex hooks are not explicitly disabled in config.toml.")
	}
	if hasActiveLegacySandbox(raw) {
		add("permissions.legacy_sandbox", CheckFail, "sandbox_mode or sandbox_workspace_write overrides permission profiles.")
	} else {
		add("permissions.legacy_sandbox", CheckPass, "No active legacy sandbox setting overrides permission profiles.")
	}

	defaults := findAssignments(raw, "default_permissions")
	selected := ""
	if len(defaults) == 1 && defaults[0].TopLevel {
		selected, _ = parseTOMLString(defaults[0].Value)
	}
	if selected != journal.ProfileName {
		add("permissions.default", CheckFail, fmt.Sprintf("default_permissions selects %q instead of %q.", selected, journal.ProfileName))
	} else {
		add("permissions.default", CheckPass, "Ward baseline is the default permission profile.")
	}

	if len(journal.ConfigEdits.ProfileAppend) == 0 || !bytes.Contains(raw, journal.ConfigEdits.ProfileAppend) {
		add("permissions.profile", CheckFail, "Ward permission profile block is missing or modified.")
	} else {
		add("permissions.profile", CheckPass, "Ward permission profile block is intact.")
	}
	if bytes.Contains(journal.ConfigEdits.ProfileAppend, []byte("[permissions."+journal.ProfileName+".network]")) {
		add("permissions.network", CheckPass, "Command network access was preserved from an explicitly migrated danger-full-access sandbox.")
	} else {
		add("permissions.network", CheckPass, "Ward did not grant command network access beyond the source permission state.")
	}
	for _, path := range []struct {
		id   string
		path string
	}{
		{"permissions.state", options.Paths.StateDir},
		{"permissions.user_policy", options.Paths.UserPolicyPath},
		{"permissions.control_config", options.Paths.ConfigFile},
		{"permissions.control_hooks", options.Paths.HooksFile},
	} {
		needle := []byte(strconv.Quote(path.path) + ` = "deny"`)
		if path.path == "" || !bytes.Contains(journal.ConfigEdits.ProfileAppend, needle) {
			add(path.id, CheckFail, "Protected Ward path is missing from the permission profile.")
		} else {
			add(path.id, CheckPass, "Ward-owned path is denied to sandboxed commands.")
		}
	}
	binaryNeedle := []byte(strconv.Quote(options.Paths.BinaryPath) + ` = "read"`)
	if options.Paths.BinaryPath == "" || !bytes.Contains(journal.ConfigEdits.ProfileAppend, binaryNeedle) {
		add("permissions.control_binary", CheckFail, "Ward executable is not sandbox read-only in the permission profile.")
	} else {
		add("permissions.control_binary", CheckPass, "Ward executable is readable and executable but not writable by sandboxed commands.")
	}
	boundariesComplete := true
	for _, directory := range readOnlyBoundaryDirectories(options.Paths) {
		needle := []byte(strconv.Quote(directory) + ` = "read"`)
		if !bytes.Contains(journal.ConfigEdits.ProfileAppend, needle) {
			boundariesComplete = false
			break
		}
	}
	if boundariesComplete {
		add("permissions.control_boundaries", CheckPass, "Ward and directory-valued credential anchors are sandbox read-only.")
	} else {
		add("permissions.control_boundaries", CheckFail, "A Ward or credential boundary directory is missing from the permission profile.")
	}
	if options.Paths.StateTopologyIncomplete {
		add("permissions.state_topology", CheckWarn, "Ward audit state has a higher writable ancestor inside the diagnosed project that cannot be frozen without broadly restricting normal work; relocating that ancestor can degrade audit continuity and remains a project release blocker.")
	} else {
		add("permissions.state_topology", CheckPass, "Ward audit state anchor has no unprotected relocatable ancestor inside the diagnosed project.")
	}
	if options.Paths.CredentialPathsIncomplete {
		add("permissions.credential_paths", CheckFail, "One or more configured credential paths are relative or otherwise cannot be represented as exact native denies.")
	} else if journal.CredentialPathsDigest == "" || journal.CredentialPathsDigest != credentialPathsDigest(options.Paths.CredentialFiles, options.Paths.CredentialDirectories) {
		add("permissions.credential_paths", CheckFail, "The environment-resolved credential path set changed after installation; reinstall Ward to replace the exact native denies.")
	} else {
		missing := false
		for _, credentialPath := range options.Paths.CredentialFiles {
			needle := []byte(strconv.Quote(credentialPath) + ` = "deny"`)
			if credentialPath == "" || !bytes.Contains(journal.ConfigEdits.ProfileAppend, needle) {
				missing = true
				break
			}
		}
		if missing {
			add("permissions.credential_paths", CheckFail, "An environment-resolved credential path is missing from the installed permission profile.")
		} else {
			add("permissions.credential_paths", CheckPass, "Environment-resolved credential paths are represented as exact native denies.")
		}
	}
	if options.Paths.CredentialTopologyIncomplete {
		add("permissions.credential_topology", CheckWarn, "At least one credential file or directory anchor has a higher writable ancestor inside the diagnosed project; the immediate path is protected, but ancestor relocation remains hook-dependent.")
	} else {
		add("permissions.credential_topology", CheckPass, "Credential anchors have no unprotected relocatable ancestor inside the diagnosed project.")
	}
	if containsInlineHooksTable(raw) {
		add("hooks.inline", CheckWarn, "config.toml also defines inline hooks; Codex merges them with hooks.json.")
	}
	if len(journal.ConfigEdits.SandboxOriginal) > 0 {
		if bytes.Count(raw, journal.ConfigEdits.SandboxReplacement) != 1 {
			add("permissions.migration", CheckFail, "Sandbox migration marker is missing or duplicated.")
		} else {
			add("permissions.migration", CheckPass, "Legacy sandbox_mode is journaled for exact restoration.")
		}
	}
}

func checkPrivateFile(report *DoctorReport, id, path string) {
	add := reportAdder(report)
	if err := audit.InspectPrivateFile(path); err != nil {
		add(id, CheckFail, "Expected private regular file is missing or has unsafe permissions.")
		return
	}
	add(id, CheckPass, "File permissions are private.")
}

func containsInlineHooksTable(raw []byte) bool {
	for _, line := range scanLines(raw) {
		text := strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(string(line.Raw), "\n"), "\r"))
		match := tableHeaderPattern.FindStringSubmatch(text)
		if len(match) == 2 && (match[1] == "hooks" || strings.HasPrefix(match[1], "hooks.")) {
			return true
		}
	}
	return false
}

func reportAdder(report *DoctorReport) func(string, CheckStatus, string) {
	return func(id string, status CheckStatus, message string) {
		report.Checks = append(report.Checks, Check{ID: id, Status: status, Message: message})
		if status == CheckFail {
			report.Healthy = false
		}
	}
}

// CleanPaths is useful to callers that need a stable display of the paths
// Doctor evaluated; it does not touch the filesystem.
func CleanPaths(paths Paths) Paths {
	paths.HomeDir = filepath.Clean(paths.HomeDir)
	paths.HooksFile = filepath.Clean(paths.HooksFile)
	paths.ConfigFile = filepath.Clean(paths.ConfigFile)
	paths.BinaryPath = filepath.Clean(paths.BinaryPath)
	paths.UserPolicyPath = filepath.Clean(paths.UserPolicyPath)
	paths.StateDir = filepath.Clean(paths.StateDir)
	for index := range paths.CredentialFiles {
		paths.CredentialFiles[index] = filepath.Clean(paths.CredentialFiles[index])
	}
	for index := range paths.CredentialDirectories {
		paths.CredentialDirectories[index] = filepath.Clean(paths.CredentialDirectories[index])
	}
	return paths
}
