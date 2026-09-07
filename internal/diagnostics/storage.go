package diagnostics

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/jgoneit/ward/internal/securefs"
)

const recordSchema = "ward-diagnostic-record/v1"
const segmentTimeFormat = "20060102T150405.000000000Z"

var segmentNamePattern = regexp.MustCompile(`^events-([0-9]{8}T[0-9]{6}\.[0-9]{9}Z)-[0-9a-f]{32}-[0-9]{6,20}\.jsonl$`)

type record struct {
	Schema     string    `json:"schema"`
	ReceivedAt time.Time `json:"received_at"`
	Generation string    `json:"collector_generation"`
	Sequence   uint64    `json:"sequence"`
	Event      Event     `json:"event"`
}

type logStore struct {
	dir        string
	generation string
	file       *os.File
	path       string
	size       int64
	openedAt   time.Time
	index      uint64
}

func (store *logStore) close() error {
	if store.file == nil {
		return nil
	}
	err := store.file.Close()
	store.file = nil
	return err
}

func (store *logStore) append(item record) error {
	data, err := json.Marshal(item)
	if err != nil {
		return errors.New("log_write")
	}
	data = append(data, '\n')
	now := item.ReceivedAt
	if store.file != nil && (store.size+int64(len(data)) > SegmentBytes || now.Sub(store.openedAt) >= 24*time.Hour) {
		if err := store.close(); err != nil {
			return errors.New("log_write")
		}
	}
	if err := store.prune(now, int64(len(data))); err != nil {
		return errors.New("log_retention")
	}
	if store.file == nil {
		store.index++
		store.path = filepath.Join(store.dir, fmt.Sprintf("events-%s-%s-%06d.jsonl", now.UTC().Format(segmentTimeFormat), store.generation, store.index))
		file, err := os.OpenFile(store.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return errors.New("log_write")
		}
		if err := securefs.SecurePrivateFile(store.path); err != nil {
			_ = file.Close()
			_ = os.Remove(store.path)
			return errors.New("log_write")
		}
		store.file = file
		store.size = 0
		store.openedAt = now
	}
	n, err := store.file.Write(data)
	if err != nil || n != len(data) {
		// Never retry a record. Restore the previous complete-line boundary if
		// possible, then use a new segment for subsequent events.
		_ = store.file.Truncate(store.size)
		_ = store.close()
		return errors.New("log_write")
	}
	store.size += int64(n)
	return nil
}

type segmentInfo struct {
	path    string
	size    int64
	created time.Time
}

func (store *logStore) prune(now time.Time, reserve int64) error {
	entries, err := os.ReadDir(store.dir)
	if err != nil {
		return err
	}
	segments := make([]segmentInfo, 0, len(entries))
	var total int64
	for _, entry := range entries {
		match := segmentNamePattern.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		path := filepath.Join(store.dir, entry.Name())
		if err := inspectRegularOwnedFile(path); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		created, err := time.Parse(segmentTimeFormat, match[1])
		if err != nil {
			return err
		}
		segments = append(segments, segmentInfo{path, info.Size(), created})
		total += info.Size()
	}
	sort.Slice(segments, func(i, j int) bool { return segments[i].path < segments[j].path })
	for _, segment := range segments {
		expired := segment.created.Before(now.Add(-RetentionAge))
		if !expired && total+reserve <= MaxLogBytes {
			continue
		}
		if segment.path == store.path && store.file != nil {
			if !expired {
				continue
			}
			if err := store.close(); err != nil {
				return err
			}
		}
		if err := os.Remove(segment.path); err != nil {
			return err
		}
		total -= segment.size
	}
	if total+reserve > MaxLogBytes {
		return errors.New("log_size_limit")
	}
	return nil
}
