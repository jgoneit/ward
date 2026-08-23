package integration

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	codexadapter "github.com/jgoneit/ward/internal/adapters/codex"
)

func TestMergeHooksInstallsOnlyAmbientPairAndPreservesUnrelatedHooks(t *testing.T) {
	original := []byte(`{
  "description":"user hooks",
  "hooks":{
    "PreToolUse":[{"matcher":"^Read$","hooks":[{"type":"command","command":"/usr/bin/custom","timeout":3}]}],
    "SessionStart":[{"matcher":"^startup$","hooks":[{"type":"command","command":"/usr/bin/start","timeout":5}]}]
  },
  "future":{"kept":true}
}`)
	binary := "/opt/Ward Tools/ward"
	merged, changed, err := mergeHooks(original, binary)
	if err != nil || !changed {
		t.Fatalf("mergeHooks() changed=%v err=%v", changed, err)
	}
	assertAmbientHookShape(t, merged, binary)
	for _, preserved := range []string{"/usr/bin/custom", "/usr/bin/start", "user hooks"} {
		if !strings.Contains(string(merged), preserved) {
			t.Fatalf("unrelated hook bytes lost %q: %s", preserved, merged)
		}
	}
	again, changed, err := mergeHooks(merged, binary)
	if err != nil || changed || string(again) != string(merged) {
		t.Fatalf("idempotent merge changed=%v err=%v", changed, err)
	}
	unmerged, changed, err := unmergeHooks(merged, binary)
	if err != nil || !changed {
		t.Fatalf("unmergeHooks() changed=%v err=%v", changed, err)
	}
	assertJSONEqual(t, unmerged, original)
}

func TestMergeHooksMigratesExactLegacyThreeHookForm(t *testing.T) {
	binary := "/tmp/ward"
	legacy := legacyHooksFixture(t, binary, []byte(`{"description":"mine","hooks":{"SessionStart":[{"matcher":"^startup$","hooks":[{"type":"command","command":"/bin/true","timeout":1}]}]}}`))
	merged, changed, err := mergeHooks(legacy, binary)
	if err != nil || !changed {
		t.Fatalf("mergeHooks() changed=%v err=%v", changed, err)
	}
	assertAmbientHookShape(t, merged, binary)
	if strings.Contains(string(merged), "codex-permission-request") || strings.Contains(string(merged), "codex-post-tool-use") || strings.Contains(string(merged), "statusMessage") {
		t.Fatalf("legacy hooks remain: %s", merged)
	}
}

func TestUnmergeHooksRecognizesLegacyInstallation(t *testing.T) {
	binary := "/tmp/ward"
	original := []byte(`{"description":"mine","hooks":{}}`)
	legacy := legacyHooksFixture(t, binary, original)
	got, changed, err := unmergeHooks(legacy, binary)
	if err != nil || !changed {
		t.Fatalf("unmergeHooks() changed=%v err=%v", changed, err)
	}
	assertJSONEqual(t, got, original)
}

func TestMergeHooksRejectsModifiedWardHandler(t *testing.T) {
	root := map[string]any{"hooks": map[string]any{"PreToolUse": []any{map[string]any{
		"matcher": codexadapter.DestructiveToolMatcher,
		"hooks":   []any{map[string]any{"type": "command", "command": "/tmp/ward hook codex-pre-tool-use", "timeout": 3}},
	}}}}
	raw, _ := json.Marshal(root)
	if _, _, err := mergeHooks(raw, "/tmp/ward"); !errors.Is(err, ErrConflict) {
		t.Fatalf("mergeHooks() error=%v, want conflict", err)
	}
}

func TestMergeHooksRejectsWardCommandUnderWrongEvent(t *testing.T) {
	binary := "/tmp/ward"
	root := map[string]any{"hooks": map[string]any{"PostToolUse": []any{map[string]any{
		"matcher": "*",
		"hooks":   []any{map[string]any{"type": "command", "command": hookCommand(binary, "codex-session-start"), "timeout": 2}},
	}}}}
	raw, _ := json.Marshal(root)
	if _, _, err := mergeHooks(raw, binary); !errors.Is(err, ErrConflict) {
		t.Fatalf("mergeHooks() error=%v, want misplaced Ward conflict", err)
	}
}

func TestHookCommandQuotesNativeWindowsPaths(t *testing.T) {
	for path, want := range map[string]string{
		`C:\Program Files\Ward\ward.exe`:     `"C:\Program Files\Ward\ward.exe" hook codex-pre-tool-use`,
		`//server/share/Ward Tools/ward.exe`: `"\\server\share\Ward Tools\ward.exe" hook codex-pre-tool-use`,
	} {
		if got := hookCommand(path, "codex-pre-tool-use"); got != want {
			t.Errorf("hookCommand(%q)=%q, want %q", path, got, want)
		}
	}
}

func TestContainsWardHandlerDecodesEscapedWindowsCommand(t *testing.T) {
	binary := `C:\Users\Example\AppData\Local\Codex\ward\bin\ward.exe`
	merged, changed, err := mergeHooks([]byte(`{"hooks":{}}`), binary)
	if err != nil || !changed {
		t.Fatalf("mergeHooks() changed=%v error=%v", changed, err)
	}
	found, err := containsWardHandler(merged, binary)
	if err != nil || !found {
		t.Fatalf("containsWardHandler() found=%v error=%v\n%s", found, err, merged)
	}
	if found, err := containsWardHandler([]byte(`{"hooks":{}}`), binary); err != nil || found {
		t.Fatalf("empty containsWardHandler() found=%v error=%v", found, err)
	}
}

func TestContainsWardHandlerRejectsStaleBinaryPath(t *testing.T) {
	raw := []byte(`{"hooks":{"PreToolUse":[{"matcher":"^Bash$","hooks":[{"type":"command","command":"/old/location/ward hook codex-pre-tool-use","timeout":2}]}]}}`)
	found, err := containsWardHandler(raw, "/new/location/ward")
	if err != nil || !found {
		t.Fatalf("containsWardHandler() found=%v error=%v", found, err)
	}
}

func TestContainsWardHandlerPreservesUnrelatedHookSubcommand(t *testing.T) {
	raw := []byte(`{"hooks":{"PreToolUse":[{"matcher":"^Bash$","hooks":[{"type":"command","command":"/usr/local/bin/acme hook codex-pre-tool-use","timeout":2}]}]}}`)
	found, err := containsWardHandler(raw, "/new/location/ward")
	if err != nil || found {
		t.Fatalf("containsWardHandler() found=%v error=%v", found, err)
	}
}

func TestMergeHooksRejectsInvalidJSONStructures(t *testing.T) {
	for name, raw := range map[string][]byte{
		"duplicate key":    []byte(`{"hooks":{},"hooks":{}}`),
		"null hooks":       []byte(`{"hooks":null}`),
		"null event":       []byte(`{"hooks":{"PreToolUse":null}}`),
		"null handler set": []byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":null}]}}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := mergeHooks(raw, "/tmp/ward"); err == nil {
				t.Fatal("mergeHooks() accepted invalid hooks")
			}
		})
	}
}

func assertAmbientHookShape(t *testing.T, raw []byte, binary string) {
	t.Helper()
	_, hooks, err := decodeHookRoot(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range wardHookSpecs {
		groups, err := decodeGroups(hooks[spec.Event])
		if err != nil {
			t.Fatal(err)
		}
		count, conflict := countDesiredHandlers(groups, spec, binary)
		if conflict || count != 1 {
			t.Fatalf("%s count=%d conflict=%v", spec.Event, count, conflict)
		}
	}
	for _, forbidden := range []string{"codex-permission-request", "codex-post-tool-use", `"timeout":10`, "statusMessage", "additionalContext"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("ambient hooks contain %q: %s", forbidden, raw)
		}
	}
}

func legacyHooksFixture(t *testing.T, binary string, original []byte) []byte {
	t.Helper()
	root, hooks, err := decodeHookRoot(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range legacyWardHookSpecs {
		groups, err := decodeGroups(hooks[spec.Event])
		if err != nil {
			t.Fatal(err)
		}
		group := map[string]any{
			"matcher": legacyAllMatcher,
			"hooks":   []map[string]any{{"type": "command", "command": hookCommand(binary, spec.Subcommand), "timeout": 10, "statusMessage": spec.StatusMessage}},
		}
		raw, _ := json.Marshal(group)
		groups = append(groups, raw)
		setGroups(hooks, spec.Event, groups)
	}
	raw, _, err := encodeHookRoot(root, hooks)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatal(err)
	}
	gotJSON, _ := json.Marshal(gotValue)
	wantJSON, _ := json.Marshal(wantValue)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("JSON differs\ngot: %s\nwant: %s", gotJSON, wantJSON)
	}
}
