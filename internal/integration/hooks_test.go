package integration

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	codexadapter "github.com/jgoneit/ward/internal/adapters/codex"
)

func TestMergeHooksInstallsExactPairAndPreservesUnrelatedHooks(t *testing.T) {
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
	assertHookShape(t, merged, binary)
	for _, preserved := range []string{"/usr/bin/custom", "/usr/bin/start", "user hooks"} {
		if !strings.Contains(string(merged), preserved) {
			t.Fatalf("unrelated hook lost %q: %s", preserved, merged)
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

func TestMergeHooksRejectsModifiedCurrentHandler(t *testing.T) {
	root := map[string]any{"hooks": map[string]any{"PreToolUse": []any{map[string]any{
		"matcher": codexadapter.DestructiveToolMatcher,
		"hooks":   []any{map[string]any{"type": "command", "command": "/tmp/ward hook codex-pre-tool-use", "timeout": 3}},
	}}}}
	raw, _ := json.Marshal(root)
	if _, _, err := mergeHooks(raw, "/tmp/ward"); !errors.Is(err, ErrConflict) {
		t.Fatalf("mergeHooks() error=%v, want conflict", err)
	}
}

func TestObsoleteWardEventsBlockV3MergeAndUnmerge(t *testing.T) {
	binary := "/tmp/ward"
	original := []byte(`{"hooks":{"PermissionRequest":[{"matcher":"*","hooks":[{"type":"command","command":"/tmp/ward hook codex-permission-request","timeout":10}]}]}}`)
	if _, _, err := mergeHooks(original, binary); !errors.Is(err, ErrConflict) {
		t.Fatalf("mergeHooks() error=%v, want conflict", err)
	}
	if _, _, err := unmergeHooks(original, binary); !errors.Is(err, ErrConflict) {
		t.Fatalf("unmergeHooks() error=%v, want conflict", err)
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

func TestContainsWardHandlerRecognizesCurrentAndObsoleteEvents(t *testing.T) {
	binary := `C:\Users\Example\AppData\Local\Codex\ward\bin\ward.exe`
	merged, changed, err := mergeHooks([]byte(`{"hooks":{}}`), binary)
	if err != nil || !changed {
		t.Fatalf("mergeHooks() changed=%v error=%v", changed, err)
	}
	if found, err := containsWardHandler(merged, binary); err != nil || !found {
		t.Fatalf("containsWardHandler() found=%v error=%v", found, err)
	}
	legacyOnly := []byte(`{"hooks":{"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/tmp/ward hook codex-post-tool-use","timeout":10}]}]}}`)
	if found, err := containsWardHandler(legacyOnly, "/tmp/ward"); err != nil || !found {
		t.Fatalf("legacy containsWardHandler() found=%v error=%v", found, err)
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

func assertHookShape(t *testing.T, raw []byte, binary string) {
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
	if strings.Contains(string(raw), "statusMessage") {
		t.Fatal("v3 hooks contain status output")
	}
}

func assertJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var left, right any
	if err := json.Unmarshal(got, &left); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &right); err != nil {
		t.Fatal(err)
	}
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	if string(leftJSON) != string(rightJSON) {
		t.Fatalf("JSON differs\ngot=%s\nwant=%s", got, want)
	}
}
