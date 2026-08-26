// Command bench-pre-hook verifies the real Ward process boundary for the
// silent defer path. It is intentionally separate from evaluator benchmarks:
// the user-visible cost includes local process startup and JSON decoding.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const iterations = 1000

func main() {
	binary := "ward"
	if runtime.GOOS == "windows" {
		binary = "ward.exe"
	}
	if len(os.Args) > 1 {
		binary = os.Args[len(os.Args)-1]
	}
	absoluteBinary, err := filepath.Abs(binary)
	check(err)
	if _, err := os.Stat(absoluteBinary); err != nil {
		fail("Ward binary is unavailable: %v", err)
	}

	root, err := os.MkdirTemp("", "ward-pre-benchmark-")
	check(err)
	defer os.RemoveAll(root)
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "project")
	codexHome := filepath.Join(home, ".codex")
	stateHome := filepath.Join(root, "state")
	configHome := filepath.Join(root, "config")
	for _, directory := range []string{project, codexHome, stateHome, configHome} {
		check(os.MkdirAll(directory, 0o700))
	}

	tool, command := "Bash", "printf ordinary"
	if runtime.GOOS == "windows" {
		command = "Write-Output ordinary"
	}
	payload, err := json.Marshal(map[string]any{
		"cwd":             project,
		"hook_event_name": "PreToolUse",
		"tool_name":       tool,
		"tool_input":      map[string]any{"command": command},
	})
	check(err)

	environment := withEnvironment(os.Environ(), map[string]string{
		"HOME":            home,
		"USERPROFILE":     home,
		"CODEX_HOME":      codexHome,
		"XDG_STATE_HOME":  stateHome,
		"XDG_CONFIG_HOME": configHome,
		"LOCALAPPDATA":    stateHome,
		"APPDATA":         configHome,
	})
	durations := make([]time.Duration, 0, iterations)
	for index := 0; index < iterations; index++ {
		var stdout, stderr bytes.Buffer
		command := exec.Command(absoluteBinary, "hook", "codex-pre-tool-use")
		command.Env = environment
		command.Stdin = bytes.NewReader(payload)
		command.Stdout = &stdout
		command.Stderr = &stderr
		started := time.Now()
		err := command.Run()
		durations = append(durations, time.Since(started))
		if err != nil || stdout.Len() != 0 || stderr.Len() != 0 {
			fail("iteration %d was not silent: err=%v stdout=%q stderr=%q", index, err, stdout.String(), stderr.String())
		}
	}

	for _, candidate := range []string{filepath.Join(stateHome, "ward"), filepath.Join(stateHome, "Ward")} {
		if _, err := os.Stat(candidate); err == nil || !os.IsNotExist(err) {
			fail("safe defer created persistent state at %s", candidate)
		}
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p95 := durations[(iterations*95)/100]
	limit := 50 * time.Millisecond
	if runtime.GOOS == "windows" {
		limit = 100 * time.Millisecond
	}
	if p95 > limit {
		fail("safe Pre process p95 %s exceeds %s", p95, limit)
	}
	fmt.Printf("PASS: %d safe Pre processes were silent and persistence-free; p95=%s limit=%s\n", iterations, p95, limit)
}

func withEnvironment(base []string, overrides map[string]string) []string {
	result := make([]string, 0, len(base)+len(overrides))
	for _, item := range base {
		key := item
		if index := strings.IndexByte(item, '='); index >= 0 {
			key = item[:index]
		}
		matched := false
		for override := range overrides {
			if strings.EqualFold(key, override) {
				matched = true
				break
			}
		}
		if !matched {
			result = append(result, item)
		}
	}
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		result = append(result, key+"="+overrides[key])
	}
	return result
}

func check(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, values ...any) {
	fmt.Fprintf(os.Stderr, "Ward Pre benchmark: "+format+"\n", values...)
	os.Exit(1)
}
