// Package diagnostics collects bounded, opt-in Ward handler diagnostics.
// Records describe Ward's own evaluation, not Host enforcement or audit proof.
package diagnostics

import (
	"path/filepath"
	"time"
)

const (
	EventSchema       = "ward-diagnostic-event/v1"
	MaxPacketBytes    = 4 << 10
	QueueCapacity     = 256
	SegmentBytes      = 1 << 20
	MaxLogBytes       = 10 << 20
	RetentionAge      = 7 * 24 * time.Hour
	heartbeatInterval = time.Second
	heartbeatMaxAge   = 5 * time.Second
	maxRuntimeBytes   = 4 << 10
)

type Paths struct {
	HomeDir    string
	CoreDir    string
	BinaryPath string
	ControlDir string
	LogDir     string
}

func NewPaths(coreDir, binaryPath, home string) Paths {
	return Paths{
		HomeDir: filepath.Clean(home), CoreDir: filepath.Clean(coreDir),
		BinaryPath: filepath.Clean(binaryPath),
		ControlDir: filepath.Join(coreDir, "diagnostics"),
		LogDir:     filepath.Join(filepath.Dir(coreDir), "diagnostics"),
	}
}

func runtimePath(paths Paths) string   { return filepath.Join(paths.ControlDir, "runtime.json") }
func heartbeatPath(paths Paths) string { return filepath.Join(paths.ControlDir, "heartbeat.json") }
