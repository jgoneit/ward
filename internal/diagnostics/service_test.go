package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWindowsBackendFailureReportsOnlyHRESULT(t *testing.T) {
	n := nativeService{platform: "windows", run: func(context.Context, string, []string, []byte) ([]byte, error) {
		return []byte(`{"BackendHResult":-2147024891,"Message":"private-backend-canary"}`), nil
	}}
	result, err := n.windowsRequest(context.Background(), windowsServiceRequest{Action: "install"})
	if err == nil || err.Error() != "diagnostics service backend failed (hresult=0x80070005)" {
		t.Fatalf("error=%v", err)
	}
	if result != (windowsServiceReply{}) {
		t.Fatalf("failure returned service state: %+v", result)
	}
}

func TestServiceDefinitionsUseUserLoginAndDedicatedCopy(t *testing.T) {
	paths, _, _ := lifecycleFixture(t)
	for _, platform := range []string{"darwin", "linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			uid := "501"
			if platform == "windows" {
				uid = "S-1-5-21-1000"
			}
			d, err := makeServiceDefinition(paths, platform, uid)
			if err != nil {
				t.Fatal(err)
			}
			if d.Binary == paths.BinaryPath || !strings.Contains(d.Binary, "ward-diagnostics") {
				t.Fatalf("binary=%s", d.Binary)
			}
			if d.Args[0] != "diagnostics" || d.Args[1] != "serve" || d.Args[len(d.Args)-1] != paths.BinaryPath {
				t.Fatalf("args=%v", d.Args)
			}
			text := string(d.Content)
			switch platform {
			case "darwin":
				if !strings.Contains(d.Path, filepath.Join("Library", "LaunchAgents")) || !strings.Contains(text, "<key>KeepAlive</key><true/>") {
					t.Fatalf("definition=%s", text)
				}
			case "linux":
				if !strings.Contains(text, "WantedBy=default.target") || !strings.Contains(text, "Restart=on-failure") || strings.Contains(text, "multi-user.target") {
					t.Fatalf("definition=%s", text)
				}
			case "windows":
				for _, part := range []string{"<LogonType>InteractiveToken</LogonType>", "<RunLevel>LeastPrivilege</RunLevel>", "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>", "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>", "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>", "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"} {
					if !strings.Contains(text, part) {
						t.Fatalf("missing %s", part)
					}
				}
			}
		})
	}
}

func TestServiceIdentityIsBoundToUserAndInstallation(t *testing.T) {
	paths, _, _ := lifecycleFixture(t)
	a, _ := makeServiceDefinition(paths, "linux", "1000")
	b, _ := makeServiceDefinition(paths, "linux", "1001")
	paths.BinaryPath = filepath.Join(filepath.Dir(paths.BinaryPath), "other-ward")
	c, _ := makeServiceDefinition(paths, "linux", "1000")
	if a.ID == b.ID || a.ID == c.ID || b.ID == c.ID {
		t.Fatalf("identities=%q %q %q", a.ID, b.ID, c.ID)
	}
}

func TestSystemdArgumentsEscapeExpansionAndWhitespace(t *testing.T) {
	got := systemdArgument(`/home/a $USER/%t/with "quote"`)
	if got != `"/home/a $$USER/%%t/with \"quote\""` {
		t.Fatalf("quoted=%s", got)
	}
}

func TestWindowsArgumentQuoting(t *testing.T) {
	for input, want := range map[string]string{"": "\"\"", "simple": "simple", `C:\User Files\`: `"C:\User Files\\"`, `a"b`: `"a\"b"`} {
		if got := windowsArgument(input); got != want {
			t.Fatalf("%q => %q want %q", input, got, want)
		}
	}
}

func TestScheduledTaskOwnershipRejectsExtraActionsAndElevatedPrincipal(t *testing.T) {
	paths, _, _ := lifecycleFixture(t)
	d, _ := makeServiceDefinition(paths, "windows", "S-1-5-21-1000")
	if !scheduledTaskMatches(d.Content, d.Content) {
		t.Fatal("self comparison failed")
	}
	for _, replacement := range [][2]string{{"LeastPrivilege", "HighestAvailable"}, {"InteractiveToken", "Password"}, {"S-1-5-21-1000", "S-1-5-18"}, {"</Actions>", "<Exec><Command>other.exe</Command></Exec></Actions>"}, {"</Triggers>", "<BootTrigger/></Triggers>"}, {"<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>", "<ExecutionTimeLimit>PT1H</ExecutionTimeLimit>"}} {
		changed := bytes.ReplaceAll(d.Content, []byte(replacement[0]), []byte(replacement[1]))
		if scheduledTaskMatches(changed, d.Content) {
			t.Fatalf("accepted altered %s", replacement[0])
		}
	}
	normalized := strings.Replace(string(d.Content), `<?xml version="1.0"?>`, `<?xml version="1.0" encoding="UTF-16"?>`, 1)
	if !strings.Contains(normalized, `encoding="UTF-16"`) {
		t.Fatal("normalization fixture does not contain a UTF-16 declaration")
	}
	normalized = strings.Replace(normalized, "<RegistrationInfo>", "<RegistrationInfo><URI>\\"+d.ID+"</URI><Author>user</Author><Date>2026-09-06</Date>", 1)
	normalized = strings.Replace(normalized, "version=\"1.2\"", "version=\"1.4\"", 1)
	if !scheduledTaskMatches([]byte(normalized), d.Content) {
		t.Fatal("rejected benign Task Scheduler normalization")
	}
}

func TestScheduledTaskExportDefaultsRemainStrict(t *testing.T) {
	paths, _, _ := lifecycleFixture(t)
	d, err := makeServiceDefinition(paths, "windows", "S-1-5-21-1000")
	if err != nil {
		t.Fatal(err)
	}
	expected := string(d.Content)
	// These fields were omitted by an actual Windows Task Scheduler export.
	// Keep this fixture independent of the implementation's defaults table.
	defaults := []struct{ name, prefix, value, changed string }{
		{"RunLevel", "", "LeastPrivilege", "HighestAvailable"},
		{"Enabled", "<LogonTrigger>", "true", "false"},
		{"AllowHardTerminate", "", "true", "false"},
		{"StartWhenAvailable", "", "false", "true"},
		{"RunOnlyIfNetworkAvailable", "", "false", "true"},
		{"AllowStartOnDemand", "", "true", "false"},
		{"Hidden", "", "false", "true"},
		{"RunOnlyIfIdle", "", "false", "true"},
		{"WakeToRun", "", "false", "true"},
		{"Priority", "", "7", "8"},
	}
	omitted := expected
	for _, field := range defaults {
		leaf := "<" + field.name + ">" + field.value + "</" + field.name + ">"
		from := field.prefix + leaf
		omitted = replaceTaskFixture(t, omitted, from, field.prefix)
		t.Run(field.name, func(t *testing.T) {
			without := replaceTaskFixture(t, expected, from, field.prefix)
			if !scheduledTaskMatches([]byte(without), d.Content) || !scheduledTaskMatches(d.Content, []byte(without)) {
				t.Fatal("rejected omission of an exported schema default")
			}
			variants := map[string]string{
				"non_default":       "<" + field.name + ">" + field.changed + "</" + field.name + ">",
				"attribute":         "<" + field.name + ` marker="changed">` + field.value + "</" + field.name + ">",
				"child":             "<" + field.name + ">" + field.value + "<Unknown/></" + field.name + ">",
				"duplicate":         leaf + leaf,
				"foreign_namespace": "<" + field.name + ` xmlns="urn:foreign">` + field.value + "</" + field.name + ">",
				"unknown_parent":    "<Unknown>" + leaf + "</Unknown>",
			}
			for name, replacement := range variants {
				t.Run(name, func(t *testing.T) {
					actual := replaceTaskFixture(t, expected, from, field.prefix+replacement)
					if scheduledTaskMatches([]byte(actual), d.Content) || scheduledTaskMatches(d.Content, []byte(actual)) {
						t.Fatal("accepted an altered execution or security setting")
					}
				})
			}
		})
	}
	if !scheduledTaskMatches([]byte(omitted), d.Content) || !scheduledTaskMatches(d.Content, []byte(omitted)) {
		t.Fatal("rejected the export with all observed defaults omitted")
	}
}

func TestScheduledTaskMutableEnabledAndMetadataRemainLeafOnly(t *testing.T) {
	paths, _, _ := lifecycleFixture(t)
	d, err := makeServiceDefinition(paths, "windows", "S-1-5-21-1000")
	if err != nil {
		t.Fatal(err)
	}
	expected := string(d.Content)
	// The suffix identifies Settings/Enabled without modifying the logon trigger.
	const enabled = "<Enabled>true</Enabled><Hidden>false</Hidden>"
	for name, leaf := range map[string]string{"true": "<Enabled>true</Enabled>", "false": "<Enabled>false</Enabled>", "omitted": ""} {
		t.Run("enabled_"+name, func(t *testing.T) {
			actual := replaceTaskFixture(t, expected, enabled, leaf+"<Hidden>false</Hidden>")
			if !scheduledTaskMatches([]byte(actual), d.Content) || !scheduledTaskMatches(d.Content, []byte(actual)) {
				t.Fatal("rejected the mutable enable state")
			}
		})
	}
	for name, leaf := range map[string]string{
		"invalid":           "<Enabled>yes</Enabled>",
		"empty":             "<Enabled/>",
		"attribute":         `<Enabled marker="changed">true</Enabled>`,
		"child":             "<Enabled>true<Unknown/></Enabled>",
		"duplicate":         "<Enabled>true</Enabled><Enabled>false</Enabled>",
		"foreign_namespace": `<Enabled xmlns="urn:foreign">true</Enabled>`,
		"unknown_parent":    "<Unknown><Enabled>true</Enabled></Unknown>",
	} {
		t.Run("enabled_reject_"+name, func(t *testing.T) {
			actual := replaceTaskFixture(t, expected, enabled, leaf+"<Hidden>false</Hidden>")
			if scheduledTaskMatches([]byte(actual), d.Content) || scheduledTaskMatches(d.Content, []byte(actual)) {
				t.Fatal("accepted invalid mutable enable metadata")
			}
		})
	}
	for _, name := range []string{"URI", "Author", "Date"} {
		t.Run("metadata_"+name, func(t *testing.T) {
			leaf := "<" + name + ">generated-value</" + name + ">"
			actual := replaceTaskFixture(t, expected, "<RegistrationInfo>", "<RegistrationInfo>"+leaf)
			if !scheduledTaskMatches([]byte(actual), d.Content) || !scheduledTaskMatches(d.Content, []byte(actual)) {
				t.Fatal("rejected generated registration metadata")
			}
			for variant, replacement := range map[string]string{
				"attribute":         "<" + name + ` marker="changed">generated-value</` + name + ">",
				"child":             "<" + name + "><Exec><Command>other.exe</Command></Exec></" + name + ">",
				"duplicate":         leaf + leaf,
				"foreign_namespace": "<" + name + ` xmlns="urn:foreign">generated-value</` + name + ">",
				"unknown_parent":    "<Unknown>" + leaf + "</Unknown>",
			} {
				t.Run(variant, func(t *testing.T) {
					actual := replaceTaskFixture(t, expected, "<RegistrationInfo>", "<RegistrationInfo>"+replacement)
					if scheduledTaskMatches([]byte(actual), d.Content) || scheduledTaskMatches(d.Content, []byte(actual)) {
						t.Fatal("accepted altered metadata structure")
					}
				})
			}
		})
	}
	for name, actual := range map[string]string{
		"foreign_task_namespace":    strings.Replace(expected, `xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"`, `xmlns="urn:foreign"`, 1),
		"foreign_version_attribute": strings.Replace(expected, `<Task version="1.2"`, `<Task version="1.2" xmlns:other="urn:foreign" other:version="1.2"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if scheduledTaskMatches([]byte(actual), d.Content) || scheduledTaskMatches(d.Content, []byte(actual)) {
				t.Fatal("accepted altered task namespace or attribute")
			}
		})
	}
}

func replaceTaskFixture(t *testing.T, source, before, after string) string {
	t.Helper()
	if strings.Count(source, before) != 1 {
		t.Fatalf("task fixture must contain exactly one %q", before)
	}
	return strings.Replace(source, before, after, 1)
}

func TestNativeLinuxInspectionRejectsDropInsAndStaleLoadedDefinition(t *testing.T) {
	paths, _, _ := lifecycleFixture(t)
	d, _ := makeServiceDefinition(paths, "linux", "1000")
	if err := ensureServiceParent(filepath.Dir(d.Path)); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnedArtifactAtomic(d.Path, d.Content, 0o600); err != nil {
		t.Fatal(err)
	}
	base := "LoadState=loaded\nActiveState=active\nFragmentPath=" + d.Path + "\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=enabled\nMainPID=123\n"
	n := nativeService{platform: "linux", userID: "1000", run: func(context.Context, string, []string, []byte) ([]byte, error) { return []byte(base), nil }}
	state, err := n.inspect(context.Background(), d)
	if err != nil || !state.Running || !state.Enabled {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	for _, change := range [][2]string{{"DropInPaths=", "DropInPaths=/tmp/other.conf"}, {"NeedDaemonReload=no", "NeedDaemonReload=yes"}, {"FragmentPath=" + d.Path, "FragmentPath=/tmp/other.service"}} {
		modified := strings.Replace(base, change[0], change[1], 1)
		n.run = func(context.Context, string, []string, []byte) ([]byte, error) { return []byte(modified), nil }
		if _, err := n.inspect(context.Background(), d); !errors.Is(err, ErrServiceConflict) {
			t.Fatalf("accepted %v err=%v", change, err)
		}
	}
}

func TestNativeMacInspectionRejectsLoadedArgumentDrift(t *testing.T) {
	paths, _, _ := lifecycleFixture(t)
	d, _ := makeServiceDefinition(paths, "darwin", "501")
	if err := ensureServiceParent(filepath.Dir(d.Path)); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnedArtifactAtomic(d.Path, d.Content, 0o600); err != nil {
		t.Fatal(err)
	}
	output := "program = " + d.Binary + "\narguments = {\n" + strings.Join(append([]string{d.Binary}, d.Args...), "\n") + "\n}\npid = 123\n"
	n := nativeService{platform: "darwin", userID: "501", run: func(context.Context, string, []string, []byte) ([]byte, error) { return []byte(output), nil }}
	state, err := n.inspect(context.Background(), d)
	if err != nil || !state.Running {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	output = strings.Replace(output, "--core-dir", "--other-dir", 1)
	if _, err := n.inspect(context.Background(), d); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("argument drift=%v", err)
	}
}

func TestNativeWindowsRegistrationUsesFixedScriptAndStructuredInput(t *testing.T) {
	paths, _, _ := lifecycleFixture(t)
	d, _ := makeServiceDefinition(paths, "windows", "S-1-5-21-1000")
	var actions []string
	n := nativeService{platform: "windows", userID: d.UserID, run: func(_ context.Context, program string, args []string, input []byte) ([]byte, error) {
		if !strings.HasSuffix(strings.ToLower(program), "powershell.exe") || args[len(args)-1] != windowsServiceScript {
			t.Fatalf("command=%s %v", program, args)
		}
		var request struct{ Action, Name, XML, UserID string }
		if err := json.Unmarshal(input, &request); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, request.Action)
		if request.Action == "inspect" {
			return json.Marshal(windowsServiceReply{true, true, true, string(d.Content)})
		}
		if request.Name != d.ID || request.UserID != d.UserID || request.XML != string(d.Content) {
			t.Fatalf("request=%+v", request)
		}
		return []byte("{}"), nil
	}}
	if err := n.install(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	state, err := n.inspect(context.Background(), d)
	if err != nil || !state.Running {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	if err := n.stop(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if err := n.remove(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(actions) != "[install inspect inspect stop remove]" {
		t.Fatalf("actions=%v", actions)
	}
}

func TestServiceArtifactWriterPreservesExistingDirectoryMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "LaunchAgents")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "owned.plist")
	if err := writeOwnedArtifactAtomic(path, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o755) {
		t.Fatalf("mode=%v err=%v", info, err)
	}
}

func TestNativeStopMissingServiceIsIdempotent(t *testing.T) {
	paths, _, _ := lifecycleFixture(t)
	d, _ := makeServiceDefinition(paths, "linux", "1000")
	var calls []string
	n := nativeService{platform: "linux", userID: "1000", run: func(_ context.Context, _ string, args []string, _ []byte) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return []byte("LoadState=not-found\n"), serviceCommandError{1}
	}}
	if err := n.stop(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || !strings.Contains(calls[0], "show") {
		t.Fatalf("mutated missing service: %v", calls)
	}
}

func TestWindowsOrphanTaskPreventsArtifactAbsentSuccess(t *testing.T) {
	paths, _, _ := lifecycleFixture(t)
	d, _ := makeServiceDefinition(paths, "windows", "S-1-5-21-1000")
	var calls []string
	n := nativeService{platform: "windows", userID: d.UserID, run: func(_ context.Context, _ string, _ []string, input []byte) ([]byte, error) {
		var request windowsServiceRequest
		if err := json.Unmarshal(input, &request); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, request.Action)
		if request.Action == "preflight" {
			return []byte("{}"), nil
		}
		if request.Action != "inspect" {
			t.Fatalf("mutated orphan task: %s", request.Action)
		}
		return json.Marshal(windowsServiceReply{Exists: true, Enabled: true, Running: false, XML: string(d.Content)})
	}}
	m := lifecycleManager{backend: n, definition: d}
	if _, err := m.disable(paths, false); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("disable=%v calls=%v", err, calls)
	}
	if _, err := m.status(paths); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("status=%v calls=%v", err, calls)
	}
}

func TestLinuxDefinitionHonorsAbsoluteXDGConfigHome(t *testing.T) {
	paths, _, _ := lifecycleFixture(t)
	configHome := filepath.Join(paths.HomeDir, "설정 with spaces")
	d, err := makeServiceDefinition(paths, "linux", "1000", configHome)
	if err != nil {
		t.Fatal(err)
	}
	if d.Path != filepath.Join(configHome, "systemd", "user", d.ID) {
		t.Fatalf("path=%s", d.Path)
	}
	if _, err := makeServiceDefinition(paths, "linux", "1000", "relative-config"); !errors.Is(err, ErrUnsupportedService) {
		t.Fatalf("relative config=%v", err)
	}
}

func TestLinuxPreflightUsesTypedManagerPathsAndRejectsMismatchBeforeWrites(t *testing.T) {
	paths, _, _ := lifecycleFixture(t)
	configHome := filepath.Join(paths.HomeDir, "설정 with spaces")
	d, _ := makeServiceDefinition(paths, "linux", "1000", configHome)
	for _, matching := range []bool{false, true} {
		t.Run(fmt.Sprint(matching), func(t *testing.T) {
			unitDir := filepath.Dir(d.Path)
			advertised := filepath.Join(paths.HomeDir, "other-config", "systemd", "user")
			if matching {
				advertised = unitDir
			}
			var calls []string
			n := nativeService{platform: "linux", userID: "1000", unitDir: unitDir, run: func(_ context.Context, program string, args []string, _ []byte) ([]byte, error) {
				calls = append(calls, program)
				if program == "systemctl" {
					return []byte("Version=254\n"), nil
				}
				if program != "busctl" || args[len(args)-1] != "UnitPath" {
					t.Fatalf("unexpected command %s %v", program, args)
				}
				return json.Marshal(map[string]any{"type": "as", "data": []string{advertised, "/usr/lib/systemd/user"}})
			}}
			err := n.preflight(context.Background())
			if matching && err != nil {
				t.Fatal(err)
			}
			if !matching && !errors.Is(err, ErrUnsupportedService) {
				t.Fatalf("mismatch=%v", err)
			}
			if fmt.Sprint(calls) != "[systemctl busctl]" {
				t.Fatalf("calls=%v", calls)
			}
			if _, err := os.Stat(configHome); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("preflight wrote config home: %v", err)
			}
		})
	}
	if managerSearchesUnitDir([]byte(`{"type":"as","data":[["/tmp/user"]]}`), "/tmp/user") {
		t.Fatal("accepted unsupported wrapped property")
	}
	if managerSearchesUnitDir([]byte(`{"type":"s","data":"/tmp/user"}`), "/tmp/user") {
		t.Fatal("accepted wrong property type")
	}
}
