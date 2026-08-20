// Package integration installs and verifies Ward's user-scoped Codex hooks
// and permission-profile fragments. Callers choose every path explicitly;
// this package never discovers or mutates a real user configuration on its
// own.
package integration

import (
	"errors"
	"path/filepath"
)

const (
	DefaultProfileName = "ward-baseline"
	journalFileName    = "integration-journal.json"
)

var (
	ErrConflict          = errors.New("Ward integration conflicts with existing configuration")
	ErrMigrationRequired = errors.New("legacy sandbox_mode requires explicit permission migration")
	ErrUnsafePath        = errors.New("Ward integration path must be absolute")
	ErrNotInstalled      = errors.New("Ward integration is not installed")
)

// Paths defines one user-scoped Codex integration. BinaryPath, UserPolicyPath,
// and StateDir are written into generated configuration, so all must be
// absolute. Tests should always use temporary paths.
type Paths struct {
	HomeDir                   string
	HooksFile                 string
	ConfigFile                string
	BinaryPath                string
	UserPolicyPath            string
	StateDir                  string
	CredentialFiles           []string
	CredentialDirectories     []string
	CredentialPathsIncomplete bool
	// Topology flags are computed by the CLI for the project Doctor is
	// diagnosing. They do not describe every ancestor below the user home.
	CredentialTopologyIncomplete bool
	StateTopologyIncomplete      bool
	// ControlTopologyIncomplete is set by the caller when a project-writable
	// ancestor can relocate Ward's dedicated config/hooks/binary anchors.
	ControlTopologyIncomplete bool
	// HomeWorkspaceTopology is true when the active workspace is HOME itself.
	// Codex permission globs cannot simultaneously recurse through that root
	// and exempt every Host-owned credential store below it.
	HomeWorkspaceTopology bool
}

func (p Paths) journalFile() string {
	return filepath.Join(p.StateDir, journalFileName)
}

// Options controls install and uninstall behavior.
type Options struct {
	Paths              Paths
	ProfileName        string
	MigratePermissions bool
	DryRun             bool
}

func (o Options) profileName() string {
	if o.ProfileName == "" {
		return DefaultProfileName
	}
	return o.ProfileName
}

// Result reports intended or completed changes. In dry-run mode no path is
// created or written even when a Changed field is true.
type Result struct {
	DryRun         bool
	Changed        bool
	HooksChanged   bool
	ConfigChanged  bool
	JournalChanged bool
	HooksFile      string
	ConfigFile     string
	JournalFile    string
}

type CheckStatus string

const (
	CheckPass CheckStatus = "pass"
	CheckFail CheckStatus = "fail"
	CheckWarn CheckStatus = "warn"
)

type Check struct {
	ID      string      `json:"id"`
	Status  CheckStatus `json:"status"`
	Message string      `json:"message"`
}

type DoctorReport struct {
	Schema  string  `json:"schema"`
	Healthy bool    `json:"healthy"`
	Checks  []Check `json:"checks"`
}
