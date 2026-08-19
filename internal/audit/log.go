package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	segmentPrefix = "events-"
	segmentSuffix = ".jsonl"
)

type anchorRecord struct {
	Schema                string    `json:"schema"`
	ProjectID             string    `json:"project_id"`
	PrunedThroughSequence uint64    `json:"pruned_through_seq"`
	PrunedThroughTime     time.Time `json:"pruned_through_time"`
	ChainMAC              string    `json:"chain_mac"`
	CreatedAt             time.Time `json:"created_at"`
	RecordMAC             string    `json:"record_mac"`
}

type headRecord struct {
	Schema       string    `json:"schema"`
	ProjectID    string    `json:"project_id"`
	LastSequence uint64    `json:"last_sequence"`
	LastMAC      string    `json:"last_mac"`
	UpdatedAt    time.Time `json:"updated_at"`
	RecordMAC    string    `json:"record_mac"`
}

type chainState struct {
	anchor *anchorRecord
	events []Event
}

type segmentInfo struct {
	index int
	day   string
	path  string
	size  int64
}

func (c chainState) nextSequence() uint64 {
	if len(c.events) > 0 {
		return c.events[len(c.events)-1].Sequence + 1
	}
	if c.anchor != nil {
		return c.anchor.PrunedThroughSequence + 1
	}
	return 1
}

func (c chainState) lastMAC() string {
	if len(c.events) > 0 {
		return c.events[len(c.events)-1].RecordMAC
	}
	if c.anchor != nil {
		return c.anchor.ChainMAC
	}
	return ""
}

func anchorWithoutMAC(anchor anchorRecord) anchorRecord {
	anchor.RecordMAC = ""
	return anchor
}

func headWithoutMAC(head headRecord) headRecord {
	head.RecordMAC = ""
	return head
}

func segmentName(index int, timestamp time.Time) string {
	return fmt.Sprintf("events-%06d-%s.jsonl", index, timestamp.UTC().Format("20060102"))
}

func parseSegmentName(name string) (int, string, bool) {
	if !strings.HasPrefix(name, segmentPrefix) || !strings.HasSuffix(name, segmentSuffix) {
		return 0, "", false
	}
	core := strings.TrimSuffix(strings.TrimPrefix(name, segmentPrefix), segmentSuffix)
	parts := strings.Split(core, "-")
	if len(parts) != 2 || len(parts[0]) != 6 || len(parts[1]) != 8 {
		return 0, "", false
	}
	index, err := strconv.Atoi(parts[0])
	if err != nil || index <= 0 {
		return 0, "", false
	}
	if _, err := time.Parse("20060102", parts[1]); err != nil {
		return 0, "", false
	}
	return index, parts[1], true
}

func listSegments(dir string) ([]segmentInfo, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list audit segments: %w", err)
	}
	segments := make([]segmentInfo, 0)
	for _, entry := range entries {
		index, day, ok := parseSegmentName(entry.Name())
		if !ok {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil, errors.New("audit segment must be a regular file")
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect audit segment: %w", err)
		}
		if err := inspectPrivateFilePermissions(filepath.Join(dir, entry.Name())); err != nil {
			return nil, integrity(0, "unsafe_segment_permissions")
		}
		segments = append(segments, segmentInfo{index: index, day: day, path: filepath.Join(dir, entry.Name()), size: info.Size()})
	}
	sort.Slice(segments, func(i, j int) bool { return segments[i].index < segments[j].index })
	for i := 1; i < len(segments); i++ {
		if segments[i].index != segments[i-1].index+1 {
			return nil, integrity(0, "segment_index_gap")
		}
	}
	return segments, nil
}

func (s *Store) readVerifiedLog(project projectState) (chainState, error) {
	return s.readVerifiedLogMode(project, true)
}

func (s *Store) readVerifiedChain(project projectState) (chainState, error) {
	return s.readVerifiedLogMode(project, false)
}

func (s *Store) readVerifiedLogMode(project projectState, verifyHeadRecord bool) (chainState, error) {
	segments, err := listSegments(project.dir)
	if err != nil {
		return chainState{}, err
	}
	state := chainState{}
	expectedSequence := uint64(1)
	expectedPreviousMAC := ""
	globalLine := 0
	for _, segment := range segments {
		file, err := openRegularFile(segment.path)
		if err != nil {
			return chainState{}, fmt.Errorf("open audit segment: %w", err)
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 4096), s.maxRecordBytes)
		segmentLines := 0
		for scanner.Scan() {
			segmentLines++
			globalLine++
			data := scanner.Bytes()
			if len(bytes.TrimSpace(data)) == 0 {
				_ = file.Close()
				return chainState{}, integrity(globalLine, "empty_record")
			}
			var envelope struct {
				Schema string `json:"schema"`
			}
			if err := json.Unmarshal(data, &envelope); err != nil {
				_ = file.Close()
				return chainState{}, integrity(globalLine, "invalid_json")
			}
			if envelope.Schema == anchorSchemaV1 {
				if globalLine != 1 || state.anchor != nil || len(state.events) != 0 {
					_ = file.Close()
					return chainState{}, integrity(globalLine, "misplaced_anchor")
				}
				var anchor anchorRecord
				if err := decodeStrictJSON(data, &anchor); err != nil {
					_ = file.Close()
					return chainState{}, integrity(globalLine, "invalid_anchor")
				}
				if anchor.ProjectID != project.id || anchor.PrunedThroughSequence == 0 || anchor.PrunedThroughTime.IsZero() || anchor.ChainMAC == "" || anchor.CreatedAt.IsZero() || anchor.RecordMAC == "" {
					_ = file.Close()
					return chainState{}, integrity(globalLine, "invalid_anchor_fields")
				}
				expectedMAC, err := signJSON(project.key, "ward-audit-anchor/v1", anchorWithoutMAC(anchor))
				if err != nil {
					_ = file.Close()
					return chainState{}, fmt.Errorf("verify audit anchor: %w", err)
				}
				if !verifyHexMAC(expectedMAC, anchor.RecordMAC) {
					_ = file.Close()
					return chainState{}, integrity(globalLine, "anchor_mac_mismatch")
				}
				state.anchor = &anchor
				expectedSequence = anchor.PrunedThroughSequence + 1
				expectedPreviousMAC = anchor.ChainMAC
				continue
			}
			if envelope.Schema != EventSchemaV1 {
				_ = file.Close()
				return chainState{}, integrity(globalLine, "unsupported_schema")
			}

			var event Event
			if err := decodeStrictJSON(data, &event); err != nil {
				_ = file.Close()
				return chainState{}, integrity(globalLine, "invalid_event")
			}
			if err := validateStoredEvent(event); err != nil {
				_ = file.Close()
				return chainState{}, integrity(globalLine, "invalid_event_fields")
			}
			if event.ProjectID != project.id {
				_ = file.Close()
				return chainState{}, integrity(globalLine, "project_mismatch")
			}
			if event.Sequence != expectedSequence {
				_ = file.Close()
				return chainState{}, integrity(globalLine, "sequence_mismatch")
			}
			if event.PreviousMAC != expectedPreviousMAC {
				_ = file.Close()
				return chainState{}, integrity(globalLine, "chain_mismatch")
			}
			expectedMAC, err := signJSON(project.key, "ward-audit-record/v1", eventWithoutMAC(event))
			if err != nil {
				_ = file.Close()
				return chainState{}, fmt.Errorf("verify audit event: %w", err)
			}
			if !verifyHexMAC(expectedMAC, event.RecordMAC) {
				_ = file.Close()
				return chainState{}, integrity(globalLine, "record_mac_mismatch")
			}
			state.events = append(state.events, event)
			expectedSequence++
			expectedPreviousMAC = event.RecordMAC
		}
		if err := scanner.Err(); err != nil {
			_ = file.Close()
			return chainState{}, integrity(globalLine+1, "record_read_failure")
		}
		if err := file.Close(); err != nil {
			return chainState{}, fmt.Errorf("close audit segment: %w", err)
		}
		if segmentLines == 0 {
			return chainState{}, integrity(globalLine, "empty_segment")
		}
	}
	if verifyHeadRecord {
		if err := verifyHead(project, state, len(segments) > 0); err != nil {
			return chainState{}, err
		}
	}
	return state, nil
}

func verifyHead(project projectState, state chainState, hasSegments bool) error {
	head, exists, err := readHead(project)
	if err != nil {
		return err
	}
	if !exists {
		if hasSegments {
			return integrity(0, "missing_head")
		}
		return nil
	}
	if !hasSegments || head.LastSequence != state.nextSequence()-1 || head.LastMAC != state.lastMAC() {
		return integrity(0, "head_chain_mismatch")
	}
	return nil
}

func readHead(project projectState) (headRecord, bool, error) {
	data, err := os.ReadFile(project.headPath)
	if errors.Is(err, os.ErrNotExist) {
		return headRecord{}, false, nil
	}
	if err != nil {
		return headRecord{}, false, fmt.Errorf("read audit head: %w", err)
	}
	info, err := os.Lstat(project.headPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return headRecord{}, false, integrity(0, "unsafe_head")
	}
	if err := inspectPrivateFilePermissions(project.headPath); err != nil {
		return headRecord{}, false, integrity(0, "unsafe_head_permissions")
	}
	var head headRecord
	if err := decodeStrictJSON(data, &head); err != nil {
		return headRecord{}, false, integrity(0, "invalid_head")
	}
	if head.Schema != "ward-audit-head/v1" || head.ProjectID != project.id || head.LastSequence == 0 || head.LastMAC == "" || head.UpdatedAt.IsZero() || head.RecordMAC == "" {
		return headRecord{}, false, integrity(0, "invalid_head_fields")
	}
	expectedMAC, err := signJSON(project.key, "ward-audit-head/v1", headWithoutMAC(head))
	if err != nil {
		return headRecord{}, false, fmt.Errorf("verify audit head: %w", err)
	}
	if !verifyHexMAC(expectedMAC, head.RecordMAC) {
		return headRecord{}, false, integrity(0, "head_mac_mismatch")
	}
	return head, true, nil
}

func writeHead(project projectState, sequence uint64, lastMAC string, timestamp time.Time) error {
	head := headRecord{
		Schema:       "ward-audit-head/v1",
		ProjectID:    project.id,
		LastSequence: sequence,
		LastMAC:      lastMAC,
		UpdatedAt:    timestamp,
	}
	var err error
	head.RecordMAC, err = signJSON(project.key, "ward-audit-head/v1", headWithoutMAC(head))
	if err != nil {
		return fmt.Errorf("sign audit head: %w", err)
	}
	encoded, err := json.Marshal(head)
	if err != nil {
		return fmt.Errorf("encode audit head: %w", err)
	}
	temporary, err := os.CreateTemp(project.dir, ".head-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary audit head: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := securePrivateFile(temporaryPath); err != nil {
		cleanup()
		return fmt.Errorf("secure temporary audit head: %w", err)
	}
	if err := writeAndSync(temporary, encoded); err != nil {
		cleanup()
		return fmt.Errorf("write temporary audit head: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("close temporary audit head: %w", err)
	}
	if err := replaceFile(temporaryPath, project.headPath); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("replace audit head: %w", err)
	}
	return syncDirectory(project.dir)
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func integrity(line int, code string) error {
	return &IntegrityError{Line: line, Code: code}
}

func openRegularFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("audit segment must be a regular file")
	}
	if err := inspectPrivateFilePermissions(path); err != nil {
		return nil, err
	}
	return os.Open(path)
}

func appendEvent(project projectState, event Event, maxSegmentBytes int64) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}
	encoded = append(encoded, '\n')
	defer zeroBytes(encoded)
	if int64(len(encoded)) > maxSegmentBytes {
		return fmt.Errorf("%w: event exceeds segment limit", ErrInvalidEvent)
	}
	segments, err := listSegments(project.dir)
	if err != nil {
		return err
	}
	day := event.Timestamp.UTC().Format("20060102")
	index := 1
	path := ""
	if len(segments) > 0 {
		last := segments[len(segments)-1]
		index = last.index
		if last.day == day && last.size+int64(len(encoded)) <= maxSegmentBytes {
			path = last.path
		} else {
			index++
		}
	}
	if path == "" {
		path = filepath.Join(project.dir, segmentName(index, event.Timestamp))
	}
	return appendLine(path, encoded)
}

func appendLine(path string, encoded []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("audit segment must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect audit segment: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open audit segment for append: %w", err)
	}
	writeErr := writeAndSync(file, encoded)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("append audit event: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close audit segment: %w", closeErr)
	}
	if err := securePrivateFile(path); err != nil {
		return fmt.Errorf("secure audit segment: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open audit directory for sync: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return fmt.Errorf("sync audit directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close audit directory: %w", closeErr)
	}
	return nil
}
