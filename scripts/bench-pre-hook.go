// Command bench-pre-hook verifies the real Ward process boundary for the
// silent defer path with an absent, available, and unavailable collector.
// Measurements include process startup, decoding, and the bounded Hook sender.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/jgoneit/ward/internal/diagnostics"
	"github.com/jgoneit/ward/internal/securefs"
)

func main() {
	if err := benchmark(); err != nil {
		fmt.Fprintf(os.Stderr, "Ward Pre benchmark: %v\n", err)
		os.Exit(1)
	}
}

func benchmark() error {
	iterations := flag.Int("iterations", 1000, "number of real Hook processes per collector state")
	absentOnly := flag.Bool("absent-only", false, "measure only absent collector; does not validate collector transport")
	flag.Parse()
	if *iterations < 1 || flag.NArg() > 1 {
		return fmt.Errorf("expected a positive iteration count and at most one binary path")
	}
	binary := "ward"
	if runtime.GOOS == "windows" {
		binary = "ward.exe"
	}
	if flag.NArg() == 1 {
		binary = flag.Arg(0)
	}
	absoluteBinary, err := filepath.Abs(binary)
	if err != nil {
		return err
	}
	if _, err := os.Stat(absoluteBinary); err != nil {
		return fmt.Errorf("Ward binary is unavailable: %w", err)
	}

	root, err := os.MkdirTemp("", "ward-pre-benchmark-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "project")
	codexHome := filepath.Join(home, ".codex")
	stateHome := filepath.Join(root, "state")
	configHome := filepath.Join(root, "config")
	for _, directory := range []string{project, codexHome, stateHome, configHome} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
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
	if err != nil {
		return err
	}

	environment := withEnvironment(os.Environ(), map[string]string{
		"HOME":            home,
		"USERPROFILE":     home,
		"CODEX_HOME":      codexHome,
		"XDG_STATE_HOME":  stateHome,
		"XDG_CONFIG_HOME": configHome,
		"LOCALAPPDATA":    stateHome,
		"APPDATA":         configHome,
	})
	measure := func(name string) error {
		durations := make([]time.Duration, 0, *iterations)
		for index := 0; index < *iterations; index++ {
			var stdout, stderr bytes.Buffer
			processCtx, stopProcess := context.WithTimeout(context.Background(), 2*time.Second)
			command := exec.CommandContext(processCtx, absoluteBinary, "hook", "codex-pre-tool-use")
			command.Env = environment
			command.Stdin = bytes.NewReader(payload)
			command.Stdout = &stdout
			command.Stderr = &stderr
			started := time.Now()
			err := command.Run()
			durations = append(durations, time.Since(started))
			stopProcess()
			if err != nil || stdout.Len() != 0 || stderr.Len() != 0 {
				return fmt.Errorf("%s iteration %d was not silent: err=%v stdout=%q stderr=%q", name, index, err, stdout.String(), stderr.String())
			}
		}
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		p95 := durations[((len(durations)*95)+99)/100-1]
		limit := 50 * time.Millisecond
		if runtime.GOOS == "windows" {
			limit = 100 * time.Millisecond
		}
		if p95 > limit {
			return fmt.Errorf("%s Pre process p95 %s exceeds %s", name, p95, limit)
		}
		fmt.Printf("PASS: collector=%s processes=%d stdout=empty stderr=empty exit=0 p95=%s limit=%s\n", name, *iterations, p95, limit)
		return nil
	}
	if err := measure("absent"); err != nil {
		return err
	}

	for _, candidate := range []string{filepath.Join(stateHome, "ward"), filepath.Join(stateHome, "Ward")} {
		if _, err := os.Stat(candidate); err == nil || !os.IsNotExist(err) {
			return fmt.Errorf("absent collector: safe defer created persistent state at %s", candidate)
		}
	}
	if *absentOnly {
		fmt.Println("Collector transport modes were not measured (-absent-only).")
		return nil
	}
	core := filepath.Join(stateHome, "ward", "core")
	if runtime.GOOS == "windows" {
		core = filepath.Join(stateHome, "Ward", "state", "core")
	}
	paths := diagnostics.NewPaths(core, absoluteBinary, home)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- diagnostics.Serve(ctx, paths) }()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			<-done
		}
	}()
	if err := waitCollector(paths); err != nil {
		return err
	}
	if err := measure("enabled"); err != nil {
		return err
	}
	probeCtx, stopProbe := context.WithTimeout(context.Background(), time.Second)
	status, err := diagnostics.Probe(probeCtx, paths)
	stopProbe()
	if err != nil || status.Received == 0 {
		return fmt.Errorf("enabled collector did not receive any Hook events: status=%+v err=%v", status, err)
	}
	// Preserve the genuine authenticated descriptor, then stop the collector.
	// Reinstating it models a crash; it never changes a real user's service.
	descriptorPath := filepath.Join(paths.ControlDir, "runtime.json")
	descriptor, err := os.ReadFile(descriptorPath)
	if err != nil {
		return err
	}
	cancel()
	err = <-done
	stopped = true
	if err != nil {
		return err
	}
	if err := os.WriteFile(descriptorPath, descriptor, 0o600); err != nil {
		return err
	}
	if err := securefs.SecurePrivateFile(descriptorPath); err != nil {
		return err
	}
	before, err := snapshotFiles(root)
	if err != nil {
		return err
	}
	if err := measure("unavailable"); err != nil {
		return err
	}
	after, err := snapshotFiles(root)
	if err != nil {
		return err
	}
	if !bytes.Equal(before, after) {
		return fmt.Errorf("unavailable collector: Hook processes changed persistent files")
	}
	fmt.Printf("Observed collector events=%d dropped=%d; these are delivery counts, not a complete Hook invocation total\n", status.Received, status.Dropped)
	return nil
}

func waitCollector(paths diagnostics.Paths) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, err := diagnostics.Probe(ctx, paths)
		cancel()
		if err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("temporary collector did not become ready")
}

func snapshotFiles(root string) ([]byte, error) {
	files := make(map[string][]byte)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err == nil {
			files[path] = data
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(files)
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
