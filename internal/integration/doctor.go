package integration

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/jgoneit/ward/internal/securefs"
	"github.com/pelletier/go-toml/v2"
)

const doctorSchemaV1 = "ward-doctor/v1"

// Doctor performs read-only checks. Messages remain useful to a human CLI;
// SessionStart exposes only failed check IDs through the Codex adapter.
func Doctor(options Options) DoctorReport {
	report := DoctorReport{Schema: doctorSchemaV1, Healthy: true}
	add := reportAdder(&report)
	if err := validateOptions(options); err != nil {
		add("paths", CheckFail, err.Error())
		return report
	}
	add("paths", CheckPass, "Integration paths are explicit and absolute.")
	if !addControlPlaneChecks(&report, options.Paths) {
		return report
	}

	journalRaw, exists, err := readOptional(options.Paths.journalFile())
	if err != nil || !exists {
		if err != nil {
			add("journal", CheckFail, err.Error())
		} else {
			add("journal", CheckFail, "Ward integration journal is missing.")
		}
		return report
	}
	journal, err := decodeJournal(journalRaw)
	if err != nil {
		add("journal", CheckFail, err.Error())
		return report
	}
	if journal.Schema != journalSchemaV3 {
		add("journal.version", CheckFail, "Ward integration journal must use v3.")
	} else {
		add("journal.version", CheckPass, "Ward integration journal uses v3.")
	}
	if journal.ProfileName != DefaultProfileName || filepath.Clean(journal.BinaryPath) != filepath.Clean(options.Paths.BinaryPath) {
		add("journal.identity", CheckFail, "Journal identity does not match this Ward installation.")
	} else {
		add("journal.identity", CheckPass, "Ward integration journal identity is valid.")
	}
	checkPrivateFile(&report, "journal.permissions", options.Paths.journalFile())

	if info, err := os.Stat(options.Paths.BinaryPath); err != nil || !info.Mode().IsRegular() {
		add("binary", CheckFail, "Configured Ward binary is missing or not a regular file.")
	} else if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		add("binary", CheckFail, "Configured Ward binary is not executable.")
	} else {
		add("binary", CheckPass, "Configured Ward binary is present.")
	}

	if hooksRaw, hooksExists, err := readOptional(options.Paths.HooksFile); err != nil || !hooksExists {
		if err != nil {
			add("hooks", CheckFail, err.Error())
		} else {
			add("hooks", CheckFail, "Codex hooks.json is missing.")
		}
	} else {
		checkHooks(&report, hooksRaw, journal.BinaryPath)
		if journal.HooksDigest != digest(hooksRaw) {
			add("hooks.changed", CheckWarn, "hooks.json changed after installation; exact Ward handlers were checked separately.")
		}
	}

	if configRaw, configExists, err := readOptional(options.Paths.ConfigFile); err != nil || !configExists {
		if err != nil {
			add("permissions", CheckFail, err.Error())
		} else {
			add("permissions", CheckFail, "Codex config.toml is missing.")
		}
	} else {
		checkConfig(&report, configRaw, journal, options)
		if journal.ConfigDigest != digest(configRaw) {
			add("permissions.changed", CheckWarn, "config.toml changed after installation; managed bytes were checked separately.")
		}
	}
	if info, err := os.Lstat(options.Paths.StateDir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		add("state", CheckFail, "Ward state directory is missing or not a real directory.")
	} else if err := securefs.InspectPrivateDirectory(options.Paths.StateDir); err != nil {
		add("state.permissions", CheckFail, "Ward state directory permissions are not private.")
	} else {
		add("state.permissions", CheckPass, "Ward state directory permissions are private.")
	}
	if options.Paths.StateTopologyIncomplete {
		add("permissions.state_topology", CheckWarn, "Ward state has a higher project-writable ancestor; the bounded immediate anchor remains protected.")
	} else {
		add("permissions.state_topology", CheckPass, "Ward state uses a bounded protected anchor.")
	}
	if options.Paths.ControlTopologyIncomplete {
		add("permissions.control_topology", CheckWarn, "A project-writable ancestor can relocate a Ward control anchor; the dedicated immediate anchors remain protected.")
	} else {
		add("permissions.control_topology", CheckPass, "Ward control files use bounded dedicated anchors outside project relocation authority.")
	}
	if options.Paths.HomeWorkspaceTopology {
		add("permissions.home_workspace_topology", CheckWarn, "HOME is the active workspace; recursive workspace Secret rules may also cover Host credential stores. Use a project subdirectory or another Host profile.")
	} else {
		add("permissions.home_workspace_topology", CheckPass, "The active workspace is narrower than HOME credential storage.")
	}
	add("permissions.layers", CheckPass, "Other Codex permission layers remain Host authority.")
	add("hooks.trust", CheckWarn, "Hook definition trust is controlled by Codex and cannot be verified by Ward; confirm it once in the Host.")
	return report
}

func checkHooks(report *DoctorReport, raw []byte, binaryPath string) {
	add := reportAdder(report)
	root, hooks, err := decodeHookRoot(raw)
	_ = root
	if err != nil {
		add("hooks", CheckFail, "hooks.json is not valid JSON: "+err.Error())
		return
	}
	allPass := true
	if event, found, err := findObsoleteWardHandler(hooks, binaryPath); err != nil {
		add("hooks.obsolete", CheckFail, err.Error())
		allPass = false
	} else if found {
		add("hooks.obsolete", CheckFail, fmt.Sprintf("Obsolete Ward %s handler is still installed.", event))
		allPass = false
	}
	for _, spec := range wardHookSpecs {
		groups, err := decodeGroups(hooks[spec.Event])
		if err != nil {
			add("hooks."+spec.Event, CheckFail, err.Error())
			allPass = false
			continue
		}
		count, conflict := countDesiredHandlers(groups, spec, binaryPath)
		if conflict || count != 1 {
			add("hooks."+spec.Event, CheckFail, fmt.Sprintf("Expected one exact Ward handler; found %d.", count))
			allPass = false
			continue
		}
		add("hooks."+spec.Event, CheckPass, "Ward handler has its canonical matcher and a 2 second command timeout.")
	}
	if allPass {
		add("hooks", CheckPass, "Exactly the two ambient Ward hook handlers are installed.")
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
		add("hooks.feature", CheckFail, "Codex hooks are explicitly disabled.")
	} else {
		add("hooks.feature", CheckPass, "Codex hooks are not explicitly disabled.")
	}
	if hasUnsupportedSandbox(raw) {
		add("permissions.sandbox_mode", CheckFail, "sandbox_mode configuration overrides permission profiles.")
	} else {
		add("permissions.sandbox_mode", CheckPass, "No sandbox_mode configuration overrides permission profiles.")
	}
	defaults := findAssignments(raw, "default_permissions")
	selected := ""
	if len(defaults) == 1 && defaults[0].TopLevel {
		selected, _ = parseTOMLString(defaults[0].Value)
	}
	if selected != journal.ProfileName {
		add("permissions.default", CheckFail, fmt.Sprintf("default_permissions selects %q instead of %q.", selected, journal.ProfileName))
	} else {
		add("permissions.default", CheckPass, "Ward's wrapper profile is selected.")
	}
	profile := journal.ConfigEdits.ProfileAppend
	if len(profile) == 0 || bytes.Count(raw, profile) != 1 {
		add("permissions.profile", CheckFail, "Ward permission profile block is missing or modified.")
		return
	}
	add("permissions.profile", CheckPass, "Ward permission profile block is intact.")
	parentNeedle := []byte("extends = " + strconv.Quote(journal.ConfigEdits.ParentProfile))
	if journal.ConfigEdits.ParentProfile == "" || !bytes.Contains(profile, parentNeedle) {
		add("permissions.parent", CheckFail, "Ward profile parent is missing or changed.")
	} else if !strings.HasPrefix(journal.ConfigEdits.ParentProfile, ":") && !namedPermissionParentSafe(raw, journal.ConfigEdits.ParentProfile) {
		add("permissions.parent", CheckFail, "Ward profile parent now contains authority Ward cannot safely inherit.")
	} else {
		add("permissions.parent", CheckPass, "Ward preserves the prior modern permission parent.")
	}
	checkNativeSecretVocabulary(report, profile)
	for _, protected := range []struct{ id, path, mode string }{
		{"permissions.state", options.Paths.StateDir, "deny"},
		{"permissions.control_config", options.Paths.ConfigFile, "deny"},
		{"permissions.control_hooks", options.Paths.HooksFile, "deny"},
		{"permissions.control_binary", options.Paths.BinaryPath, "read"},
	} {
		needle := []byte(strconv.Quote(protected.path) + ` = "` + protected.mode + `"`)
		if protected.path == "" || !bytes.Contains(profile, needle) {
			add(protected.id, CheckFail, "A Ward control or state path is not protected.")
		} else {
			add(protected.id, CheckPass, "Ward control or state path is protected.")
		}
	}
	bounded := true
	for _, directory := range readOnlyBoundaryDirectories(options.Paths) {
		if !bytes.Contains(profile, []byte(strconv.Quote(directory)+` = "read"`)) {
			bounded = false
		}
	}
	codexRootRead := []byte(strconv.Quote(filepath.Dir(options.Paths.ConfigFile)) + ` = "read"`)
	if !bounded || bytes.Contains(profile, codexRootRead) {
		add("permissions.control_boundaries", CheckFail, "Ward control topology is missing or broader than the bounded Ward anchors.")
	} else {
		add("permissions.control_boundaries", CheckPass, "Only bounded Ward-owned relocation anchors are read-only.")
	}
	if containsInlineHooksTable(raw) {
		var parsed map[string]any
		if err := toml.Unmarshal(raw, &parsed); err == nil && containsWardConfigHookValue(parsed["hooks"], options.Paths.BinaryPath) {
			add("hooks.inline_ward", CheckFail, "Inline configuration also references Ward; duplicate Hook execution cannot be excluded.")
		} else {
			add("hooks.inline", CheckWarn, "config.toml also defines unrelated inline hooks; Codex merges them with hooks.json.")
		}
	}
	if len(journal.ConfigEdits.SandboxOriginal) > 0 && bytes.Count(raw, journal.ConfigEdits.SandboxReplacement) != 1 {
		add("permissions.rollback_marker", CheckFail, "The live-transition rollback marker is missing or duplicated.")
	}
}

func checkNativeSecretVocabulary(report *DoctorReport, profile []byte) {
	add := reportAdder(report)
	missing := false
	for _, rule := range workspaceSecretRules() {
		if !bytes.Contains(profile, []byte(rule)) {
			missing = true
			break
		}
	}
	if missing {
		add("permissions.native_secret_probe", CheckFail, "A reviewed workspace secret rule is missing.")
	} else {
		add("permissions.native_secret_probe", CheckPass, "All reviewed workspace secret probes are represented.")
	}
	forbidden := []string{
		`"~/.aws/credentials" = "deny"`, `"~/.config/gh/hosts.yml" = "deny"`, `"~/.docker/config.json" = "deny"`,
		`"*.key" = "deny"`, `"**/*.key" = "deny"`, `"*.pem" = "deny"`, `"**/*.pem" = "deny"`,
		`"*-secret.yml" = "deny"`, `"**/*-secret.yml" = "deny"`, `"*credentials*.json" = "deny"`, `".env.*" = "deny"`,
		`"privkey0.pem" = "deny"`,
	}
	for _, needle := range forbidden {
		if bytes.Contains(profile, []byte(needle)) {
			add("permissions.native_minimal_probe", CheckFail, "The native profile contains a broad or HOME credential rule.")
			return
		}
	}
	add("permissions.native_minimal_probe", CheckPass, "Public PEM, generic YAML, templates, and HOME auth stores remain outside Ward's native carve-out.")
}

func checkPrivateFile(report *DoctorReport, id, path string) {
	add := reportAdder(report)
	if err := securefs.InspectPrivateFile(path); err != nil {
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
