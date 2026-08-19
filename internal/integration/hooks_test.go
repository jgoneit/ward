package integration

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestMergeAndUnmergeHooksPreservesUnrelatedHooks(t *testing.T) {
	original := []byte(`{
  "description": "user hooks",
  "hooks": {
    "PreToolUse": [{"matcher":"^Bash$","hooks":[{"type":"command","command":"/usr/bin/custom","timeout":3}]}],
    "SessionStart": [{"hooks":[{"type":"command","command":"/usr/bin/start"}]}]
  },
  "future": {"kept": true}
}`)
	binary := "/opt/Ward Tools/ward"
	merged, changed, err := mergeHooks(original, binary)
	if err != nil {
		t.Fatalf("mergeHooks() error = %v", err)
	}
	if !changed {
		t.Fatal("mergeHooks() did not report a change")
	}
	for _, command := range []string{
		`'/opt/Ward Tools/ward' hook codex-pre-tool-use`,
		`'/opt/Ward Tools/ward' hook codex-permission-request`,
		`'/opt/Ward Tools/ward' hook codex-post-tool-use`,
	} {
		if !strings.Contains(string(merged), command) {
			t.Fatalf("merged hooks missing %q: %s", command, merged)
		}
	}

	again, changed, err := mergeHooks(merged, binary)
	if err != nil || changed || string(again) != string(merged) {
		t.Fatalf("idempotent merge = changed %v, err %v", changed, err)
	}

	unmerged, changed, err := unmergeHooks(merged, binary)
	if err != nil {
		t.Fatalf("unmergeHooks() error = %v", err)
	}
	if !changed {
		t.Fatal("unmergeHooks() did not report a change")
	}
	assertJSONEqual(t, unmerged, original)
}

func TestMergeHooksRejectsModifiedWardHandler(t *testing.T) {
	raw := []byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/tmp/other hook codex-pre-tool-use","timeout":10,"statusMessage":"Ward: evaluating tool request"}]}]}}`)
	_, _, err := mergeHooks(raw, "/tmp/ward")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("mergeHooks() error = %v, want conflict", err)
	}
}

func TestHookCommandQuotesWindowsPath(t *testing.T) {
	got := hookCommand(`C:\Program Files\Ward\ward.exe`, "codex-pre-tool-use")
	want := `"C:\Program Files\Ward\ward.exe" hook codex-pre-tool-use`
	if got != want {
		t.Fatalf("hookCommand() = %q, want %q", got, want)
	}
}

func TestMergeHooksRejectsDuplicateJSONKeys(t *testing.T) {
	_, _, err := mergeHooks([]byte(`{"hooks":{},"hooks":{}}`), "/tmp/ward")
	if err == nil {
		t.Fatal("mergeHooks() accepted duplicate JSON keys")
	}
}

func TestMergeHooksRejectsNullStructuralValues(t *testing.T) {
	for name, raw := range map[string][]byte{
		"hooks object":   []byte(`{"hooks":null}`),
		"event groups":   []byte(`{"hooks":{"PreToolUse":null}}`),
		"group handlers": []byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":null}]}}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := mergeHooks(raw, "/tmp/ward"); !errors.Is(err, ErrConflict) {
				t.Fatalf("mergeHooks() error = %v, want conflict", err)
			}
		})
	}
}

func assertJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("got invalid JSON: %v", err)
	}
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("want invalid JSON: %v", err)
	}
	gotJSON, _ := json.Marshal(gotValue)
	wantJSON, _ := json.Marshal(wantValue)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("JSON differs\ngot:  %s\nwant: %s", gotJSON, wantJSON)
	}
}
