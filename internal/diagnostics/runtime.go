package diagnostics

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"time"
)

const runtimeSchema = "ward-diagnostic-runtime/v1"

type runtimeDescriptor struct {
	Schema     string    `json:"schema"`
	Generation string    `json:"generation"`
	Port       uint16    `json:"port"`
	Key        string    `json:"key"`
	PID        int       `json:"pid"`
	StartedAt  time.Time `json:"started_at"`
}

type RuntimeStatus struct {
	Present     bool      `json:"present"`
	Fresh       bool      `json:"fresh"`
	Generation  string    `json:"generation"`
	PID         int       `json:"pid"`
	StartedAt   time.Time `json:"started_at"`
	HeartbeatAt time.Time `json:"heartbeat_at"`
	Received    uint64    `json:"received"`
	Dropped     uint64    `json:"dropped"`
	WriteErrors uint64    `json:"write_errors"`
	LastError   string    `json:"last_error,omitempty"`
}

func readRuntime(paths Paths, strict bool) (runtimeDescriptor, []byte, error) {
	var result runtimeDescriptor
	var data []byte
	var err error
	if strict {
		data, err = readPrivateFile(runtimePath(paths), maxRuntimeBytes)
	} else {
		data, err = readPrivateFileCheap(runtimePath(paths), maxRuntimeBytes)
	}
	if err != nil {
		return result, nil, err
	}
	if err := strictJSON(data, &result); err != nil {
		return result, nil, errors.New("runtime_invalid")
	}
	if result.Schema != runtimeSchema || !validHex(result.Generation, 16) || result.Port == 0 ||
		!validHex(result.Key, 32) || result.PID <= 0 || result.StartedAt.IsZero() {
		return runtimeDescriptor{}, nil, errors.New("runtime_invalid")
	}
	key, _ := hex.DecodeString(result.Key)
	return result, key, nil
}

// SendBestEffort sends at most one bounded datagram, with no response wait,
// retries, child process, stdout/stderr output, or persistent write. The CLI
// bounds its total wait including regular-file metadata I/O.
func SendBestEffort(ctx context.Context, paths Paths, event Event) {
	if ctx.Err() != nil {
		return
	}
	payload, err := marshalEvent(event)
	if err != nil {
		return
	}
	runtime, key, err := readRuntime(paths, false)
	if err != nil || ctx.Err() != nil {
		return
	}
	data, err := encodePacket(key, runtime.Generation, "event", payload)
	if err != nil {
		return
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Millisecond)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return
	}
	if ctx.Err() != nil {
		return
	}
	_, _ = conn.WriteToUDP(data, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(runtime.Port)})
}

// ReadRuntimeStatus reports stored collector metadata. Fresh is heartbeat
// freshness, not process identity or a complete delivery guarantee.
func ReadRuntimeStatus(paths Paths) (RuntimeStatus, error) {
	runtime, _, err := readRuntime(paths, true)
	if errors.Is(err, os.ErrNotExist) {
		return RuntimeStatus{}, nil
	}
	if err != nil {
		return RuntimeStatus{}, errors.New("runtime_unavailable")
	}
	status := RuntimeStatus{Present: true, Generation: runtime.Generation, PID: runtime.PID, StartedAt: runtime.StartedAt}
	data, err := readPrivateFile(heartbeatPath(paths), maxRuntimeBytes)
	if errors.Is(err, os.ErrNotExist) {
		return status, nil
	}
	if err != nil {
		return status, errors.New("heartbeat_unavailable")
	}
	var heartbeat RuntimeStatus
	if err := strictJSON(data, &heartbeat); err != nil || heartbeat.Generation != runtime.Generation || heartbeat.PID != runtime.PID ||
		!stringSet("", "log_write", "log_retention", "heartbeat_write")[heartbeat.LastError] {
		return status, errors.New("heartbeat_invalid")
	}
	heartbeat.Present = true
	age := time.Since(heartbeat.HeartbeatAt)
	heartbeat.Fresh = age >= 0 && age <= heartbeatMaxAge
	return heartbeat, nil
}

type probeMessage struct {
	Nonce string `json:"nonce"`
}
type probeResponse struct {
	Nonce  string        `json:"nonce"`
	Status RuntimeStatus `json:"status"`
}

// Probe is an authenticated challenge for explicit management readiness only.
// Policy hooks never invoke it and never wait for a collector acknowledgement.
func Probe(ctx context.Context, paths Paths) (RuntimeStatus, error) {
	runtime, key, err := readRuntime(paths, true)
	if err != nil {
		return RuntimeStatus{}, errors.New("collector_unavailable")
	}
	nonce, err := randomHex(16)
	if err != nil {
		return RuntimeStatus{}, errors.New("probe_random")
	}
	payload, _ := json.Marshal(probeMessage{nonce})
	data, err := encodePacket(key, runtime.Generation, "probe", payload)
	if err != nil {
		return RuntimeStatus{}, err
	}
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(runtime.Port)})
	if err != nil {
		return RuntimeStatus{}, errors.New("collector_unavailable")
	}
	defer conn.Close()
	deadline := time.Now().Add(250 * time.Millisecond)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return RuntimeStatus{}, errors.New("probe_deadline")
	}
	if ctx.Err() != nil {
		return RuntimeStatus{}, ctx.Err()
	}
	if _, err := conn.Write(data); err != nil {
		return RuntimeStatus{}, errors.New("collector_unavailable")
	}
	buffer := make([]byte, MaxPacketBytes+1)
	n, err := conn.Read(buffer)
	if err != nil {
		return RuntimeStatus{}, errors.New("collector_unavailable")
	}
	reply, err := decodePacket(buffer[:n], key, runtime.Generation)
	if err != nil || reply.Kind != "probe_reply" {
		return RuntimeStatus{}, errors.New("probe_invalid")
	}
	var response probeResponse
	if err := strictJSON(reply.Payload, &response); err != nil || response.Nonce != nonce ||
		response.Status.Generation != runtime.Generation || response.Status.PID != runtime.PID {
		return RuntimeStatus{}, errors.New("probe_invalid")
	}
	response.Status.Present = true
	response.Status.Fresh = true
	return response.Status, nil
}

func randomHex(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
