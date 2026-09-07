package diagnostics

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type collectorState struct {
	sync.Mutex
	status RuntimeStatus
}

func (state *collectorState) snapshot() RuntimeStatus {
	state.Lock()
	defer state.Unlock()
	result := state.status
	result.HeartbeatAt = time.Now().UTC()
	return result
}

func (state *collectorState) enqueue(queue chan<- record, event Event, receivedAt time.Time) {
	state.Lock()
	state.status.Received++
	item := record{recordSchema, receivedAt, state.status.Generation, state.status.Received, event}
	state.Unlock()
	select {
	case queue <- item:
	default:
		state.Lock()
		state.status.Dropped++
		state.Unlock()
	}
}

func (state *collectorState) writeRecord(store *logStore, item record) {
	err := store.append(item)
	if err == nil {
		return
	}
	state.Lock()
	state.status.WriteErrors++
	state.status.Dropped++
	state.status.LastError = err.Error()
	state.Unlock()
}

// Serve owns all diagnostic persistence. It is independent of hook decisions;
// a failed/stopped collector can only lose observations.
func Serve(ctx context.Context, paths Paths) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := validatePaths(paths); err != nil {
		return err
	}
	if err := ensurePrivateDirectory(paths.ControlDir); err != nil {
		return errors.New("control_directory_unavailable")
	}
	if err := ensurePrivateDirectory(paths.LogDir); err != nil {
		return errors.New("log_directory_unavailable")
	}
	unlock, err := lockCollector(filepath.Join(paths.ControlDir, "collector.lock"))
	if err != nil {
		return errors.New("collector_already_running")
	}
	defer unlock()
	generation, err := randomHex(16)
	if err != nil {
		return errors.New("collector_random")
	}
	keyHex, err := randomHex(32)
	if err != nil {
		return errors.New("collector_random")
	}
	key, _ := hex.DecodeString(keyHex)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return errors.New("collector_listen")
	}
	defer conn.Close()
	started := time.Now().UTC()
	runtime := runtimeDescriptor{runtimeSchema, generation, uint16(conn.LocalAddr().(*net.UDPAddr).Port), keyHex, os.Getpid(), started}
	state := &collectorState{status: RuntimeStatus{Present: true, Fresh: true, Generation: generation, PID: os.Getpid(), StartedAt: started}}
	store := &logStore{dir: paths.LogDir, generation: generation}
	if err := store.prune(started, 0); err != nil {
		return errors.New("log_retention")
	}
	heartbeat, _ := json.Marshal(state.snapshot())
	if err := writePrivateFileAtomic(heartbeatPath(paths), heartbeat); err != nil {
		return errors.New("heartbeat_write")
	}
	runtimeData, _ := json.Marshal(runtime)
	if err := writePrivateFileAtomic(runtimePath(paths), runtimeData); err != nil {
		return errors.New("runtime_write")
	}
	defer removeOwnRuntime(paths, generation)

	queue := make(chan record, QueueCapacity)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		defer store.close()
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case item, open := <-queue:
				if !open {
					return
				}
				state.writeRecord(store, item)
			case now := <-ticker.C:
				if err := store.prune(now, 0); err != nil {
					state.Lock()
					state.status.LastError = "log_retention"
					state.status.WriteErrors++
					state.Unlock()
				}
				data, _ := json.Marshal(state.snapshot())
				if err := writePrivateFileAtomic(heartbeatPath(paths), data); err != nil {
					state.Lock()
					state.status.LastError = "heartbeat_write"
					state.status.WriteErrors++
					state.Unlock()
				}
			}
		}
	}()
	defer func() { close(queue); <-writerDone }()
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-writerDone:
		}
	}()
	buffer := make([]byte, MaxPacketBytes+1)
	for {
		n, peer, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("collector_read")
		}
		if !peer.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			continue
		}
		message, err := decodePacket(buffer[:n], key, generation)
		if err != nil {
			state.Lock()
			state.status.Dropped++
			state.Unlock()
			continue
		}
		switch message.Kind {
		case "probe":
			var request probeMessage
			if strictJSON(message.Payload, &request) != nil || !validHex(request.Nonce, 16) {
				continue
			}
			payload, _ := json.Marshal(probeResponse{request.Nonce, state.snapshot()})
			reply, err := encodePacket(key, generation, "probe_reply", payload)
			if err == nil {
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
				_, _ = conn.WriteToUDP(reply, peer)
			}
		case "event":
			event, err := decodeEvent(message.Payload)
			if err != nil {
				state.Lock()
				state.status.Dropped++
				state.Unlock()
				continue
			}
			state.enqueue(queue, event, time.Now().UTC())
		}
	}
}

func removeOwnRuntime(paths Paths, generation string) {
	current, _, err := readRuntime(paths, false)
	if err != nil || current.Generation != generation {
		return
	}
	_ = os.Remove(runtimePath(paths))
	_ = os.Remove(heartbeatPath(paths))
}
