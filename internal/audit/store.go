package audit

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxInputBytes  = 1 << 20
	defaultMaxRecordBytes = 1 << 20
	defaultLockTimeout    = 2 * time.Second
)

type Options struct {
	StateDir        string
	Now             func() time.Time
	Random          io.Reader
	MaxInputBytes   int
	MaxRecordBytes  int
	SegmentMaxBytes int64
	RetentionDays   int
	ProjectMaxBytes int64
	TotalMaxBytes   int64
	LockTimeout     time.Duration
	// StaleLockAfter is retained for source compatibility. Ward now uses
	// kernel-backed locks and never steals a lock based on wall-clock age.
	StaleLockAfter time.Duration
}

type Store struct {
	stateDir        string
	projectsDir     string
	keyPath         string
	catalogPath     string
	catalogLockPath string
	masterKey       []byte
	now             func() time.Time
	maxInputBytes   int
	maxRecordBytes  int
	segmentMaxBytes int64
	retentionDays   int
	projectMaxBytes int64
	totalMaxBytes   int64
	lockTimeout     time.Duration
	mu              sync.Mutex
	// scanCheckpoint is an internal test seam for a slow segment reader. The
	// production path leaves it nil and performs only the context check.
	scanCheckpoint func(context.Context) error
}

type projectState struct {
	id         string
	key        []byte
	dir        string
	headPath   string
	lockPath   string
	markerPath string
}

func NewStore(options Options) (*Store, error) {
	return NewStoreContext(context.Background(), options)
}

// NewStoreContext applies the caller's deadline to audit identity and catalog
// initialization. Hook callers use this constructor so audit degradation can
// never consume the Host's entire command-hook timeout.
func NewStoreContext(ctx context.Context, options Options) (*Store, error) {
	return openStore(ctx, options, true)
}

// OpenStore opens an initialized audit store without creating or repairing
// any path. Read-only commands and Doctor should use this constructor so a
// missing or insecure store cannot become a false PASS through inspection.
func OpenStore(options Options) (*Store, error) {
	return OpenStoreContext(context.Background(), options)
}

// OpenStoreContext is the read-only, deadline-aware form of OpenStore.
func OpenStoreContext(ctx context.Context, options Options) (*Store, error) {
	return openStore(ctx, options, false)
}

func openStore(ctx context.Context, options Options, create bool) (*Store, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	lockTimeout := options.LockTimeout
	if lockTimeout <= 0 {
		lockTimeout = defaultLockTimeout
	}
	stateDir := strings.TrimSpace(options.StateDir)
	if stateDir == "" {
		var err error
		stateDir, err = DefaultStateDir()
		if err != nil {
			return nil, err
		}
	}
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("audit state directory must be absolute")
	}
	stateDir = filepath.Clean(stateDir)
	stateExisted := true
	if _, err := os.Lstat(stateDir); errors.Is(err, os.ErrNotExist) {
		stateExisted = false
	} else if err != nil {
		return nil, fmt.Errorf("inspect audit state directory: %w", err)
	}
	if create {
		if err := ensurePrivateDirectoryContext(ctx, stateDir); err != nil {
			return nil, fmt.Errorf("prepare audit state directory: %w", err)
		}
	} else if err := inspectPrivateDirectoryContext(ctx, stateDir); err != nil {
		return nil, err
	}
	projectsDir := filepath.Join(stateDir, "projects")
	if create {
		if err := ensurePrivateDirectoryContext(ctx, projectsDir); err != nil {
			return nil, fmt.Errorf("prepare project state directory: %w", err)
		}
	} else if err := inspectPrivateDirectoryContext(ctx, projectsDir); err != nil {
		return nil, err
	}

	randomSource := options.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	catalogLockPath := filepath.Join(stateDir, projectCatalogLockFile)
	mode := lockShared
	if create {
		mode = lockExclusive
	}
	identityLock, err := acquireFileLock(ctx, catalogLockPath, mode, lockTimeout, create)
	if err != nil {
		return nil, err
	}
	masterKey, err := openAuditIdentityContext(ctx, stateDir, projectsDir, create, !stateExisted, now, randomSource)
	identityLock.release()
	if err != nil {
		return nil, err
	}

	store := &Store{
		stateDir:        stateDir,
		projectsDir:     projectsDir,
		keyPath:         filepath.Join(stateDir, "master.key"),
		catalogPath:     filepath.Join(stateDir, projectCatalogFile),
		catalogLockPath: catalogLockPath,
		masterKey:       masterKey,
		now:             now,
		maxInputBytes:   options.MaxInputBytes,
		maxRecordBytes:  options.MaxRecordBytes,
		segmentMaxBytes: options.SegmentMaxBytes,
		retentionDays:   options.RetentionDays,
		projectMaxBytes: options.ProjectMaxBytes,
		totalMaxBytes:   options.TotalMaxBytes,
		lockTimeout:     lockTimeout,
	}
	if store.maxInputBytes <= 0 {
		store.maxInputBytes = defaultMaxInputBytes
	}
	if store.maxRecordBytes <= 0 {
		store.maxRecordBytes = defaultMaxRecordBytes
	}
	if store.segmentMaxBytes <= 0 {
		store.segmentMaxBytes = DefaultSegmentMaxBytes
	}
	if store.retentionDays <= 0 {
		store.retentionDays = DefaultRetentionDays
	}
	if store.projectMaxBytes <= 0 {
		store.projectMaxBytes = DefaultProjectMaxBytes
	}
	if store.totalMaxBytes <= 0 {
		store.totalMaxBytes = DefaultTotalMaxBytes
	}
	return store, nil
}

func (s *Store) StateDir() string { return s.stateDir }

func (s *Store) RetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		Days:            s.retentionDays,
		SegmentMaxBytes: s.segmentMaxBytes,
		ProjectMaxBytes: s.projectMaxBytes,
		TotalMaxBytes:   s.totalMaxBytes,
	}
}

// ProjectID derives the pseudonymous identifier used to partition audit state.
// It never stores or returns the canonical root path.
func (s *Store) ProjectID(cwd string) (string, error) {
	root, err := CanonicalProjectRoot(cwd)
	if err != nil {
		return "", err
	}
	return deriveProjectID(s.masterKey, root), nil
}

func (s *Store) ProjectLogPath(cwd string) (string, error) {
	project, exists, err := s.existingProject(context.Background(), cwd)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", ErrNotInitialized
	}
	segments, err := listSegments(project.dir)
	if err != nil {
		return "", err
	}
	if len(segments) > 0 {
		return segments[len(segments)-1].path, nil
	}
	return filepath.Join(project.dir, segmentName(1, s.now().UTC())), nil
}

func (s *Store) project(cwd string) (projectState, error) {
	id, err := s.ProjectID(cwd)
	if err != nil {
		return projectState{}, err
	}
	dir := filepath.Join(s.projectsDir, id)
	return projectState{
		id:         id,
		key:        deriveProjectKey(s.masterKey, id),
		dir:        dir,
		headPath:   filepath.Join(dir, "head.json"),
		lockPath:   filepath.Join(dir, projectLockFile),
		markerPath: filepath.Join(dir, projectMarkerFile),
	}, nil
}

// Record persists a metadata-only audit event for Ward's current sparse writer.
// New records are limited to PreToolUse deny and error decisions. Historical
// ward-audit-event/v1 records can contain defer, PermissionRequest, and Post
// events; read-side validation deliberately remains broader so those chains
// continue to verify without migration or rewriting.
//
// Its error is observability for the caller; the method has no
// evaluator-decision return and cannot modify the supplied Decision.
func (s *Store) Record(ctx context.Context, input RecordInput) error {
	return s.record(ctx, input, validateRecordInput)
}

func (s *Store) record(ctx context.Context, input RecordInput, validate func(RecordInput) error) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	event, project, err := s.prepareEvent(input, validate)
	if err != nil {
		return err
	}
	if err := contextError(ctx); err != nil {
		return err
	}

	if err := s.lockContext(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if err := s.ensureRegisteredProject(ctx, project); err != nil {
		return err
	}
	lock, err := acquireFileLock(ctx, project.lockPath, lockExclusive, s.lockTimeout, false)
	if err != nil {
		return err
	}
	defer lock.release()

	chain, err := s.readVerifiedLogContext(ctx, project)
	if err != nil {
		return err
	}
	event.Sequence = chain.nextSequence()
	event.PreviousMAC = chain.lastMAC()
	event.RecordMAC, err = signJSONContext(ctx, project.key, "ward-audit-record/v1", eventWithoutMAC(event))
	if err != nil {
		return fmt.Errorf("sign audit event: %w", err)
	}
	head, err := prepareHeadContext(ctx, project, event.Sequence, event.RecordMAC, s.now().UTC())
	if err != nil {
		return err
	}
	if err := appendEventContext(ctx, project, event, s.segmentMaxBytes); err != nil {
		return err
	}
	// Once the event append commits, finish its already-signed head update even
	// if the caller deadline expires between the two writes. All unbounded
	// chain scanning and signing happened under ctx before this commit phase.
	return writePreparedHeadContext(context.WithoutCancel(ctx), project, head)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("audit context is nil")
	}
	return ctx.Err()
}

func (s *Store) lockContext(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if s.mu.TryLock() {
		return nil
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if s.mu.TryLock() {
				return nil
			}
		}
	}
}

func (s *Store) prepareEvent(input RecordInput, validate func(RecordInput) error) (Event, projectState, error) {
	if err := validate(input); err != nil {
		return Event{}, projectState{}, err
	}
	project, err := s.project(input.CWD)
	if err != nil {
		return Event{}, projectState{}, err
	}
	canonicalInput, err := canonicalJSON(input.ToolInput, s.maxInputBytes)
	if err != nil {
		return Event{}, projectState{}, err
	}
	defer zeroBytes(canonicalInput)

	timestamp := input.Timestamp
	if timestamp.IsZero() {
		timestamp = s.now()
	}
	timestamp = timestamp.UTC()

	sessionFingerprint := fingerprintOptional(project.key, "ward-session/v1", input.SessionID)
	turnFingerprint := fingerprintOptional(project.key, "ward-turn/v1", input.TurnID)
	toolUseFingerprint := fingerprintOptional(project.key, "ward-tool-use/v1", input.ToolUseID)
	inputFingerprint := keyedHex(project.key, "ward-tool-input/v1", []byte(input.ToolName), canonicalInput)
	correlationFingerprint := inputFingerprint
	if input.CorrelationInput != nil {
		canonicalCorrelationInput, err := canonicalJSON(input.CorrelationInput, s.maxInputBytes)
		if err != nil {
			return Event{}, projectState{}, err
		}
		defer zeroBytes(canonicalCorrelationInput)
		correlationFingerprint = keyedHex(project.key, "ward-tool-input/v1", []byte(input.ToolName), canonicalCorrelationInput)
	}
	toolFingerprint := keyedHex(project.key, "ward-tool/v1", []byte(input.ToolName))
	event := Event{
		Schema:             EventSchemaV1,
		Timestamp:          timestamp,
		Phase:              input.Phase,
		HostDisposition:    input.HostDisposition,
		ProjectID:          project.id,
		SessionFingerprint: sessionFingerprint,
		TurnFingerprint:    turnFingerprint,
		ToolUseFingerprint: toolUseFingerprint,
		InputFingerprint:   inputFingerprint,
		ToolFingerprint:    toolFingerprint,
		// Tool-use identifiers and phase-specific host metadata can differ
		// between PreToolUse and PermissionRequest. request_fp uses the adapter's
		// normalized correlation input while input_fp authenticates raw ToolInput.
		RequestFingerprint: keyedHex(project.key, "ward-request/v1", []byte(sessionFingerprint), []byte(turnFingerprint), []byte(correlationFingerprint)),
		ToolKind:           input.ToolKind,
		Decision:           input.Decision,
		RuleID:             input.RuleID,
		RiskClass:          input.RiskClass,
		CoverageGapCode:    sanitizeCoverageGapCode(input.CoverageGapCode),
		PermissionMode:     sanitizePermissionMode(input.PermissionMode),
		EngineVersion:      input.EngineVersion,
	}
	if len(input.PolicyMaterial) > 0 {
		event.PolicyFingerprint = keyedHex(project.key, "ward-policy/v1", input.PolicyMaterial)
	}
	return event, project, nil
}

func validateRecordInput(input RecordInput) error {
	if err := validateRecordMetadata(input); err != nil {
		return err
	}
	if input.Phase != PhasePre {
		return fmt.Errorf("%w: new audit records require pre phase", ErrInvalidEvent)
	}
	if input.HostDisposition != HostUnknown {
		return fmt.Errorf("%w: new audit records require unknown host disposition", ErrInvalidEvent)
	}
	if input.CoverageGapCode != "" {
		return fmt.Errorf("%w: new audit records must not contain a coverage gap", ErrInvalidEvent)
	}
	switch input.Decision {
	case DecisionDeny, DecisionError:
		return nil
	default:
		return fmt.Errorf("%w: new audit records require deny or error decision", ErrInvalidEvent)
	}
}

// validateHistoricalRecordInput accepts the complete ward-audit-event/v1
// vocabulary. It is read-side compatibility logic, not an alternate current
// writer contract.
func validateHistoricalRecordInput(input RecordInput) error {
	if err := validateRecordMetadata(input); err != nil {
		return err
	}
	if input.CoverageGapCode != "" && input.Decision != DecisionDefer {
		return fmt.Errorf("%w: coverage gap requires defer decision", ErrInvalidEvent)
	}
	switch input.Phase {
	case PhasePre:
		if input.HostDisposition != HostUnknown {
			return fmt.Errorf("%w: pre phase requires unknown host disposition", ErrInvalidEvent)
		}
	case PhasePermissionRequest:
		if input.HostDisposition != HostApprovalRequested {
			return fmt.Errorf("%w: permission_request requires approval_requested", ErrInvalidEvent)
		}
	case PhasePost:
		if input.HostDisposition != HostPostObserved {
			return fmt.Errorf("%w: post phase requires post_observed", ErrInvalidEvent)
		}
	default:
		return fmt.Errorf("%w: unsupported phase", ErrInvalidEvent)
	}
	if input.Phase == PhasePost {
		if input.Decision != "" {
			return fmt.Errorf("%w: post phase must not assert a decision", ErrInvalidEvent)
		}
	} else {
		switch input.Decision {
		case DecisionDeny, DecisionDefer, DecisionError:
		default:
			return fmt.Errorf("%w: unsupported decision", ErrInvalidEvent)
		}
	}
	return nil
}

func validateRecordMetadata(input RecordInput) error {
	if strings.TrimSpace(input.CWD) == "" {
		return fmt.Errorf("%w: cwd is required", ErrInvalidEvent)
	}
	if input.ToolName == "" || len(input.ToolName) > 256 {
		return fmt.Errorf("%w: invalid tool name", ErrInvalidEvent)
	}
	if len(input.RuleID) > 256 || len(input.RiskClass) > 256 || len(input.EngineVersion) > 128 {
		return fmt.Errorf("%w: metadata field too long", ErrInvalidEvent)
	}
	switch input.ToolKind {
	case ToolShell, ToolPatch, ToolMCP, ToolLocal, ToolUnknown:
	default:
		return fmt.Errorf("%w: unsupported tool kind", ErrInvalidEvent)
	}
	return nil
}

func validateStoredEvent(event Event) error {
	if event.Schema != EventSchemaV1 || event.Sequence == 0 || event.Timestamp.IsZero() || event.ProjectID == "" || event.InputFingerprint == "" || event.ToolFingerprint == "" || event.RequestFingerprint == "" || event.RecordMAC == "" {
		return ErrInvalidEvent
	}
	if event.PermissionMode != "" && !validPersistedPermissionMode(event.PermissionMode) {
		return ErrInvalidEvent
	}
	if event.CoverageGapCode != "" && !validPersistedCoverageGapCode(event.CoverageGapCode) {
		return ErrInvalidEvent
	}
	return validateHistoricalRecordInput(RecordInput{
		CWD:             "persisted",
		Phase:           event.Phase,
		HostDisposition: event.HostDisposition,
		ToolName:        "persisted",
		ToolKind:        event.ToolKind,
		Decision:        event.Decision,
		RuleID:          event.RuleID,
		RiskClass:       event.RiskClass,
		CoverageGapCode: string(event.CoverageGapCode),
		PermissionMode:  string(event.PermissionMode),
		EngineVersion:   event.EngineVersion,
	})
}

func sanitizePermissionMode(value string) PermissionMode {
	switch PermissionMode(value) {
	case PermissionDefault, PermissionAcceptEdits, PermissionPlan, PermissionDontAsk, PermissionBypassPermissions:
		return PermissionMode(value)
	case "":
		return ""
	default:
		return PermissionUnknown
	}
}

func validPersistedPermissionMode(value PermissionMode) bool {
	switch value {
	case PermissionDefault, PermissionAcceptEdits, PermissionPlan, PermissionDontAsk, PermissionBypassPermissions, PermissionUnknown:
		return true
	default:
		return false
	}
}

func sanitizeCoverageGapCode(value string) CoverageGapCode {
	code := CoverageGapCode(value)
	if code == "" {
		return ""
	}
	if validPersistedCoverageGapCode(code) && code != CoverageGapUnknown {
		return code
	}
	return CoverageGapUnknown
}

func validPersistedCoverageGapCode(value CoverageGapCode) bool {
	switch value {
	case CoverageGapAmbiguousCMD,
		CoverageGapAmbiguousPowerShell,
		CoverageGapAmbiguousPowerShellOptions,
		CoverageGapBuiltinDispatch,
		CoverageGapComplexCommandWrapper,
		CoverageGapComplexEnvWrapper,
		CoverageGapComplexFileOperands,
		CoverageGapComplexNohupWrapper,
		CoverageGapComplexSudoWrapper,
		CoverageGapDynamicAdditivePrefix,
		CoverageGapDynamicFindPath,
		CoverageGapDynamicGlobalOption,
		CoverageGapDynamicInterpreterPayload,
		CoverageGapDynamicPatchPath,
		CoverageGapDynamicPath,
		CoverageGapDynamicShellWord,
		CoverageGapDynamicWrapper,
		CoverageGapEmptyWindowsCommand,
		CoverageGapFindCommandAction,
		CoverageGapInlineShellInput,
		CoverageGapInterpreterPayload,
		CoverageGapMalformedPatchPath,
		CoverageGapMissingCommand,
		CoverageGapMissingStructuredMoveRoles,
		CoverageGapMissingStructuredPath,
		CoverageGapNestedShellLimit,
		CoverageGapNohupStdinSemantics,
		CoverageGapOpaqueCommandDispatch,
		CoverageGapShellFunction,
		CoverageGapShellParseError,
		CoverageGapUnrecognizedPatch,
		CoverageGapUnresolvedHomeTarget,
		CoverageGapUnsupportedDockerGlobalOption,
		CoverageGapUnsupportedGitGlobalOption,
		CoverageGapUnsupportedGlobalOption,
		CoverageGapUnsupportedKubectlGlobalOption,
		CoverageGapUnsupportedTool,
		CoverageGapUnknown:
		return true
	default:
		return false
	}
}

func fingerprintOptional(key []byte, domain, value string) string {
	if value == "" {
		return ""
	}
	return keyedHex(key, domain, []byte(value))
}

func signJSON(key []byte, domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	defer zeroBytes(encoded)
	return keyedHex(key, domain, encoded), nil
}

func signJSONContext(ctx context.Context, key []byte, domain string, value any) (string, error) {
	if err := contextError(ctx); err != nil {
		return "", err
	}
	mac, err := signJSON(key, domain, value)
	if err != nil {
		return "", err
	}
	if err := contextError(ctx); err != nil {
		return "", err
	}
	return mac, nil
}

func verifyHexMAC(expected, actual string) bool {
	expectedBytes, expectedErr := hex.DecodeString(expected)
	actualBytes, actualErr := hex.DecodeString(actual)
	if expectedErr != nil || actualErr != nil || len(expectedBytes) != len(actualBytes) {
		return false
	}
	return subtle.ConstantTimeCompare(expectedBytes, actualBytes) == 1
}

func eventWithoutMAC(event Event) Event {
	event.RecordMAC = ""
	return event
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func ensurePrivateDirectory(path string) error {
	return ensurePrivateDirectoryContext(context.Background(), path)
}

func ensurePrivateDirectoryContext(ctx context.Context, path string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("state path must be a real directory")
	}
	return securePrivateDirectoryContext(ctx, path)
}

func inspectPrivateDirectory(path string) error {
	return inspectPrivateDirectoryContext(context.Background(), path)
}

func inspectPrivateDirectoryContext(ctx context.Context, path string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrNotInitialized, filepath.Base(path))
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("state path must be a real directory")
	}
	return inspectPrivateDirectoryPermissionsContext(ctx, path)
}

func loadExistingMasterKey(path string) ([]byte, error) {
	return loadExistingMasterKeyContext(context.Background(), path)
}

func loadExistingMasterKeyContext(ctx context.Context, path string) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, fmt.Errorf("inspect audit master key: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("audit master key must be a regular file")
	}
	if err := inspectPrivateFilePermissionsContext(ctx, path); err != nil {
		return nil, fmt.Errorf("unsafe audit master key permissions: %w", err)
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read audit master key: %w", err)
	}
	if len(key) != masterKeySize {
		zeroBytes(key)
		return nil, errors.New("audit master key has invalid length")
	}
	if err := contextError(ctx); err != nil {
		zeroBytes(key)
		return nil, err
	}
	return key, nil
}

func loadOrCreateMasterKey(path string, randomSource io.Reader) ([]byte, error) {
	return loadOrCreateMasterKeyContext(context.Background(), path, randomSource)
}

func loadOrCreateMasterKeyContext(ctx context.Context, path string, randomSource io.Reader) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("audit master key must be a regular file")
		}
		if err := securePrivateFileContext(ctx, path); err != nil {
			return nil, fmt.Errorf("secure audit master key: %w", err)
		}
		key, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read audit master key: %w", err)
		}
		if len(key) != masterKeySize {
			zeroBytes(key)
			return nil, errors.New("audit master key has invalid length")
		}
		if err := contextError(ctx); err != nil {
			zeroBytes(key)
			return nil, err
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect audit master key: %w", err)
	}

	key := make([]byte, masterKeySize)
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(randomSource, key); err != nil {
		return nil, fmt.Errorf("generate audit master key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		zeroBytes(key)
		return loadOrCreateMasterKeyContext(ctx, path, randomSource)
	}
	if err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("create audit master key: %w", err)
	}
	writeErr := writeAndSync(file, key)
	closeErr := file.Close()
	if writeErr != nil {
		zeroBytes(key)
		_ = os.Remove(path)
		return nil, fmt.Errorf("write audit master key: %w", writeErr)
	}
	if closeErr != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("close audit master key: %w", closeErr)
	}
	if err := securePrivateFileContext(ctx, path); err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("secure audit master key: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("sync audit master key directory: %w", err)
	}
	return key, nil
}

func writeAndSync(file *os.File, value []byte) error {
	if _, err := file.Write(value); err != nil {
		return err
	}
	return file.Sync()
}
