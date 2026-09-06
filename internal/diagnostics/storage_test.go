package diagnostics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jgoneit/ward/internal/securefs"
)

func TestStorageWriteFailureCountsLossWithoutRetryingRecord(t *testing.T) {
	paths := fixturePaths(t)
	if err := ensurePrivateDirectory(paths.LogDir); err != nil {
		t.Fatal(err)
	}
	generation := strings.Repeat("a", 32)
	store := &logStore{dir: paths.LogDir, generation: generation}
	defer store.close()
	now := time.Now().UTC()
	first := record{recordSchema, now, generation, 1, exampleEvent()}
	if err := store.append(first); err != nil {
		t.Fatal(err)
	}
	firstPath := store.path
	before, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	// Closing the writer injects a real OS write failure without filling the
	// host disk or changing permissions outside this temporary fixture.
	if err := store.file.Close(); err != nil {
		t.Fatal(err)
	}
	state := &collectorState{status: RuntimeStatus{Generation: generation, Received: 2}}
	state.writeRecord(store, record{recordSchema, now, generation, 2, exampleEvent()})
	status := state.snapshot()
	if status.LastError != "log_write" || status.WriteErrors != 1 || status.Dropped != 1 {
		t.Fatalf("write failure was not isolated/countable: %+v", status)
	}
	after, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("existing complete record changed after failed write")
	}
	state.writeRecord(store, record{recordSchema, now, generation, 3, exampleEvent()})
	entries, err := os.ReadDir(paths.LogDir)
	if err != nil {
		t.Fatal(err)
	}
	var sequences []uint64
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(paths.LogDir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
			var item record
			if err := json.Unmarshal(line, &item); err != nil {
				t.Fatal(err)
			}
			sequences = append(sequences, item.Sequence)
		}
	}
	if len(sequences) != 2 || sequences[0] != 1 || sequences[1] != 3 {
		t.Fatalf("failed record retried or recovery lost: %v", sequences)
	}
}

func TestStorageRetentionFailureHasStaticCodeAndPreservesConflict(t *testing.T) {
	paths := fixturePaths(t)
	if err := ensurePrivateDirectory(paths.LogDir); err != nil {
		t.Fatal(err)
	}
	generation := strings.Repeat("a", 32)
	now := time.Now().UTC()
	conflict := filepath.Join(paths.LogDir, fmt.Sprintf("events-%s-%s-000001.jsonl", now.Format(segmentTimeFormat), generation))
	if err := os.Mkdir(conflict, 0o700); err != nil {
		t.Fatal(err)
	}
	store := &logStore{dir: paths.LogDir, generation: generation}
	state := &collectorState{status: RuntimeStatus{Generation: generation, Received: 1}}
	state.writeRecord(store, record{recordSchema, now, generation, 1, exampleEvent()})
	status := state.snapshot()
	if status.LastError != "log_retention" || status.WriteErrors != 1 || status.Dropped != 1 {
		t.Fatalf("retention failure: %+v", status)
	}
	if info, err := os.Stat(conflict); err != nil || !info.IsDir() {
		t.Fatalf("conflicting path changed: %v", err)
	}
}

func TestStorageRotatesAtSegmentBound(t *testing.T) {
	paths := fixturePaths(t)
	if err := ensurePrivateDirectory(paths.LogDir); err != nil {
		t.Fatal(err)
	}
	store := &logStore{dir: paths.LogDir, generation: strings.Repeat("a", 32)}
	defer store.close()
	event := exampleEvent()
	id := strings.Repeat("x", 128)
	event.SessionID = &id
	event.TurnID = &id
	event.ToolUseID = &id
	now := time.Now().UTC()
	for i := 0; i < 1600; i++ {
		if err := store.append(record{recordSchema, now, store.generation, uint64(i + 1), event}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(paths.LogDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatal("segment did not rotate")
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > SegmentBytes {
			t.Fatalf("segment exceeded limit: %d", info.Size())
		}
	}
}

func TestRetentionBoundsAgeAndTotalWithoutTouchingUnownedFiles(t *testing.T) {
	paths := fixturePaths(t)
	if err := ensurePrivateDirectory(paths.LogDir); err != nil {
		t.Fatal(err)
	}
	generation := strings.Repeat("a", 32)
	now := time.Now().UTC()
	for i := 0; i < 11; i++ {
		created := now.Add(-time.Duration(i) * time.Hour)
		if i == 10 {
			created = now.Add(-RetentionAge - time.Hour)
		}
		name := fmt.Sprintf("events-%s-%s-%06d.jsonl", created.Format(segmentTimeFormat), generation, i)
		path := filepath.Join(paths.LogDir, name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(SegmentBytes); err != nil {
			t.Fatal(err)
		}
		_ = file.Close()
		if err := securefs.SecurePrivateFile(path); err != nil {
			t.Fatal(err)
		}
	}
	unowned := filepath.Join(paths.LogDir, "user-notes.txt")
	if err := os.WriteFile(unowned, []byte("retain"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := &logStore{dir: paths.LogDir, generation: generation}
	if err := store.prune(now, 1024); err != nil {
		t.Fatal(err)
	}
	var total int64
	entries, err := os.ReadDir(paths.LogDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		match := segmentNamePattern.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		created, err := time.Parse(segmentTimeFormat, match[1])
		if err != nil {
			t.Fatal(err)
		}
		if created.Before(now.Add(-RetentionAge)) {
			t.Fatal("expired segment retained")
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}
	if total+1024 > MaxLogBytes {
		t.Fatalf("retention bound exceeded: %d", total)
	}
	if data, err := os.ReadFile(unowned); err != nil || string(data) != "retain" {
		t.Fatalf("changed unrelated file: %s %v", data, err)
	}
}
