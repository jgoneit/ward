package diagnostics

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jgoneit/ward/internal/securefs"
)

func fixturePaths(t *testing.T) Paths {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := securefs.SecurePrivateDirectory(home); err != nil {
		t.Fatal(err)
	}
	return NewPaths(filepath.Join(home, "state", "core"), filepath.Join(home, "bin", "ward"), home)
}

func startCollector(t *testing.T, paths Paths) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, paths) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		probeCtx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, err := Probe(probeCtx, paths)
		stop()
		if err == nil {
			return cancel, done
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("collector ended before ready: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	t.Fatal("collector did not become ready")
	return nil, nil
}

func stopCollector(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collector did not stop")
	}
}

func TestCollectorReceivesOnlyWardEventsAndRotatesIdentity(t *testing.T) {
	paths := fixturePaths(t)
	if status, err := ReadRuntimeStatus(paths); err != nil || status.Present {
		t.Fatalf("absent: %+v %v", status, err)
	}
	cancel, done := startCollector(t, paths)
	old, key, err := readRuntime(paths, true)
	if err != nil {
		t.Fatal(err)
	}
	event := exampleEvent()
	session := "session_abc"
	event.SessionID = &session
	SendBestEffort(context.Background(), paths, event)
	var status RuntimeStatus
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		status, err = Probe(context.Background(), paths)
		if err == nil && status.Received == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || status.Received != 1 {
		cancel()
		t.Fatalf("no event: %+v %v", status, err)
	}
	stopCollector(t, cancel, done)
	if _, err := os.Stat(runtimePath(paths)); !os.IsNotExist(err) {
		t.Fatalf("runtime survived clean stop: %v", err)
	}
	entries, err := os.ReadDir(paths.LogDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one segment: %d", len(entries))
	}
	data, err := os.ReadFile(filepath.Join(paths.LogDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), old.Key) || strings.Contains(string(data), `"mac"`) {
		t.Fatal("transport credentials persisted")
	}
	var item record
	if err := strictJSON(data, &item); err != nil {
		t.Fatal(err)
	}
	if item.Event.SessionID == nil || *item.Event.SessionID != session || item.Sequence != 1 {
		t.Fatalf("wrong persisted event: %+v", item)
	}
	cancel, done = startCollector(t, paths)
	defer stopCollector(t, cancel, done)
	current, _, err := readRuntime(paths, true)
	if err != nil {
		t.Fatal(err)
	}
	if current.Generation == old.Generation || current.Key == old.Key {
		t.Fatal("collector reused identity")
	}
	// Deliver a validly signed packet from the former generation to the new
	// endpoint. It must not enter the event log.
	payload, _ := marshalEvent(event)
	packet, _ := encodePacket(key, old.Generation, "event", payload)
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(current.Port)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Write(packet)
	_ = conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		status, err = Probe(context.Background(), paths)
		if err == nil && status.Dropped > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if status.Received != 0 || status.Dropped == 0 {
		t.Fatalf("stale packet accepted: %+v", status)
	}
}

func TestCollectorExcludesSecondConcurrentServer(t *testing.T) {
	paths := fixturePaths(t)
	cancel, done := startCollector(t, paths)
	defer stopCollector(t, cancel, done)
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := Serve(ctx, paths); err == nil || err.Error() != "collector_already_running" {
		t.Fatalf("second collector: %v", err)
	}
}

func TestSendFailureDoesNotCreateState(t *testing.T) {
	paths := fixturePaths(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	SendBestEffort(ctx, paths, exampleEvent())
	SendBestEffort(context.Background(), paths, exampleEvent())
	if _, err := os.Stat(paths.ControlDir); !os.IsNotExist(err) {
		t.Fatalf("send created state: %v", err)
	}
}

func TestCollectorQueueDropsOverflowWithoutBlocking(t *testing.T) {
	state := &collectorState{status: RuntimeStatus{Generation: strings.Repeat("a", 32)}}
	queue := make(chan record, QueueCapacity)
	done := make(chan struct{})
	go func() {
		for index := 0; index < QueueCapacity+17; index++ {
			state.enqueue(queue, exampleEvent(), time.Now())
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("overflow blocked collector")
	}
	status := state.snapshot()
	if len(queue) != QueueCapacity || status.Received != QueueCapacity+17 || status.Dropped != 17 {
		t.Fatalf("incorrect bounded-queue accounting: depth=%d status=%+v", len(queue), status)
	}
	for sequence := uint64(1); sequence <= QueueCapacity; sequence++ {
		if item := <-queue; item.Sequence != sequence {
			t.Fatalf("receipt ordering changed: %d want %d", item.Sequence, sequence)
		}
	}
}

func TestPrivateRuntimeRejectsSymlinkAndOversizedDescriptor(t *testing.T) {
	paths := fixturePaths(t)
	if err := ensurePrivateDirectory(paths.ControlDir); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFileAtomic(runtimePath(paths), []byte(strings.Repeat("x", maxRuntimeBytes+1))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readRuntime(paths, false); err == nil {
		t.Fatal("oversized runtime accepted")
	}
	if err := os.Remove(runtimePath(paths)); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(paths.ControlDir, "target")
	data, _ := json.Marshal(runtimeDescriptor{runtimeSchema, strings.Repeat("a", 32), 12345, strings.Repeat("b", 64), os.Getpid(), time.Now()})
	if err := writePrivateFileAtomic(target, data); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, runtimePath(paths)); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err := readRuntime(paths, false); err == nil {
		t.Fatal("symlink runtime accepted")
	}
}
