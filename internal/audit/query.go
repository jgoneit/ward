package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *Store) Verify(ctx context.Context, cwd string) (Verification, error) {
	project, exists, err := s.existingProject(ctx, cwd)
	if err != nil {
		return Verification{}, err
	}
	result := Verification{ProjectID: project.id, Valid: true}
	if !exists {
		return result, nil
	}

	state, err := s.readLocked(ctx, project)
	if err != nil {
		result.Valid = false
		return result, err
	}
	populateVerification(&result, state)
	return result, nil
}

func populateVerification(result *Verification, state chainState) {
	result.Records = len(state.events)
	if state.anchor != nil {
		result.PrunedThroughSequence = state.anchor.PrunedThroughSequence
		result.PrunedThroughTime = state.anchor.PrunedThroughTime
		result.LastSequence = state.anchor.PrunedThroughSequence
		result.LastMAC = state.anchor.ChainMAC
	}
	if len(state.events) > 0 {
		result.FirstSequence = state.events[0].Sequence
		last := state.events[len(state.events)-1]
		result.LastSequence = last.Sequence
		result.LastMAC = last.RecordMAC
	}
}

func (s *Store) Show(ctx context.Context, cwd string, filter Filter) ([]Event, error) {
	if filter.Limit < 0 {
		return nil, errors.New("audit filter limit must not be negative")
	}
	project, exists, err := s.existingProject(ctx, cwd)
	if err != nil || !exists {
		return nil, err
	}
	state, err := s.readLocked(ctx, project)
	if err != nil {
		return nil, err
	}
	result := make([]Event, 0, len(state.events))
	for _, event := range state.events {
		if !matchesFilter(event, filter) {
			continue
		}
		result = append(result, event)
		if filter.Limit > 0 && len(result) == filter.Limit {
			break
		}
	}
	return result, nil
}

func matchesFilter(event Event, filter Filter) bool {
	if !filter.Since.IsZero() && event.Timestamp.Before(filter.Since) {
		return false
	}
	if !filter.Until.IsZero() && !event.Timestamp.Before(filter.Until) {
		return false
	}
	if filter.Phase != "" && event.Phase != filter.Phase {
		return false
	}
	if filter.Decision != "" && event.Decision != filter.Decision {
		return false
	}
	if filter.HostDisposition != "" && event.HostDisposition != filter.HostDisposition {
		return false
	}
	if filter.RuleID != "" && event.RuleID != filter.RuleID {
		return false
	}
	return true
}

func (s *Store) Stats(ctx context.Context, cwd string, filter Filter) (Stats, error) {
	projectID, err := s.ProjectID(cwd)
	if err != nil {
		return Stats{}, err
	}
	events, err := s.Show(ctx, cwd, filter)
	if err != nil {
		return Stats{}, err
	}
	stats := Stats{
		ProjectID:         projectID,
		ByPhase:           make(map[Phase]uint64),
		ByDecision:        make(map[Decision]uint64),
		ByHostDisposition: make(map[HostDisposition]uint64),
		ByRule:            make(map[string]uint64),
		ByCoverageGapCode: make(map[CoverageGapCode]uint64),
	}
	for _, event := range events {
		stats.Total++
		stats.ByPhase[event.Phase]++
		stats.ByHostDisposition[event.HostDisposition]++
		if event.Decision != "" {
			stats.ByDecision[event.Decision]++
		}
		if event.RuleID != "" {
			stats.ByRule[event.RuleID]++
		}
		if event.CoverageGapCode != "" {
			stats.ByCoverageGapCode[event.CoverageGapCode]++
		}
		if stats.FirstTimestamp.IsZero() {
			stats.FirstTimestamp = event.Timestamp
		}
		stats.LastTimestamp = event.Timestamp
	}
	verification, verifyErr := s.Verify(ctx, cwd)
	if verifyErr != nil {
		return Stats{}, verifyErr
	}
	stats.PrunedThroughSequence = verification.PrunedThroughSequence
	return stats, nil
}

// Prune is intentionally disabled in v0.1. A safe implementation requires an
// atomic generation manifest across segments and head; the legacy mixed-file
// replacement path is not exposed.
func (s *Store) Prune(ctx context.Context, cwd string, before time.Time) (PruneResult, error) {
	if before.IsZero() {
		return PruneResult{}, errors.New("prune cutoff is required")
	}
	return PruneResult{}, ErrPruneDisabled
}

// RetentionStatus is read-only. It verifies the current project's retained
// chain and reports both the per-project and aggregate byte caps without
// creating state or lock files.
func (s *Store) RetentionStatus(ctx context.Context, cwd string) (RetentionStatus, error) {
	project, exists, err := s.existingProject(ctx, cwd)
	if err != nil {
		return RetentionStatus{}, err
	}
	if exists {
		if _, err := s.readLocked(ctx, project); err != nil {
			return RetentionStatus{}, err
		}
	}
	projectBytes, err := projectAuditBytes(project.dir)
	if err != nil {
		return RetentionStatus{}, err
	}
	totalBytes, err := totalAuditBytes(filepath.Join(s.stateDir, "projects"))
	if err != nil {
		return RetentionStatus{}, err
	}
	return RetentionStatus{
		ProjectID:       project.id,
		Policy:          s.RetentionPolicy(),
		ProjectBytes:    projectBytes,
		TotalBytes:      totalBytes,
		ProjectExceeded: projectBytes > s.projectMaxBytes,
		TotalExceeded:   totalBytes > s.totalMaxBytes,
	}, nil
}

// PruneRetention previews Ward's age and per-project retention policy when
// dryRun is true. Mutation is disabled in v0.1 until segment/head generations
// can be committed atomically. Aggregate-cap overflow is reported separately
// because deleting the selected project must not compensate for other projects.
func (s *Store) PruneRetention(ctx context.Context, cwd string, dryRun bool) (RetentionPruneResult, error) {
	if !dryRun {
		return RetentionPruneResult{}, ErrPruneDisabled
	}
	project, exists, err := s.existingProject(ctx, cwd)
	if err != nil {
		return RetentionPruneResult{}, err
	}
	cutoff := s.now().UTC().AddDate(0, 0, -s.retentionDays)
	if !exists {
		status, statusErr := s.RetentionStatus(ctx, cwd)
		if statusErr != nil {
			return RetentionPruneResult{}, statusErr
		}
		result := RetentionPruneResult{
			ProjectID:             project.id,
			DryRun:                true,
			Cutoff:                cutoff,
			ProjectBytesBefore:    status.ProjectBytes,
			ProjectBytesAfter:     status.ProjectBytes,
			TotalBytesBefore:      status.TotalBytes,
			TotalBytesAfter:       status.TotalBytes,
			ProjectLimitSatisfied: !status.ProjectExceeded,
			TotalLimitSatisfied:   !status.TotalExceeded,
		}
		if !result.TotalLimitSatisfied {
			return result, ErrGlobalRetentionRequired
		}
		return result, nil
	}

	state, err := s.readLocked(ctx, project)
	if err != nil {
		return RetentionPruneResult{}, err
	}
	result, err := s.retentionPlan(project, state, cutoff, true)
	if err == nil && !result.TotalLimitSatisfied {
		err = ErrGlobalRetentionRequired
	}
	return result, err
}

func (s *Store) retentionPlan(project projectState, state chainState, cutoff time.Time, dryRun bool) (RetentionPruneResult, error) {
	projectBefore, err := projectAuditBytes(project.dir)
	if err != nil {
		return RetentionPruneResult{}, err
	}
	totalBefore, err := totalAuditBytes(filepath.Join(s.stateDir, "projects"))
	if err != nil {
		return RetentionPruneResult{}, err
	}
	cut := 0
	for cut < len(state.events) && state.events[cut].Timestamp.Before(cutoff) {
		cut++
	}
	projectAfter := projectBefore
	totalAfter := totalBefore
	for {
		if cut > 0 {
			projectAfter, err = s.estimatedPrunedBytes(project, state, cut)
			if err != nil {
				return RetentionPruneResult{}, err
			}
			totalAfter = totalBefore - projectBefore + projectAfter
		}
		if projectAfter <= s.projectMaxBytes || cut == len(state.events) {
			break
		}
		cut++
	}
	result := RetentionPruneResult{
		ProjectID:             project.id,
		DryRun:                dryRun,
		Cutoff:                cutoff,
		Removed:               cut,
		Remaining:             len(state.events) - cut,
		ProjectBytesBefore:    projectBefore,
		ProjectBytesAfter:     projectAfter,
		TotalBytesBefore:      totalBefore,
		TotalBytesAfter:       totalAfter,
		ProjectLimitSatisfied: projectAfter <= s.projectMaxBytes,
		TotalLimitSatisfied:   totalAfter <= s.totalMaxBytes,
	}
	if cut > 0 {
		terminal := state.events[cut-1]
		result.PrunedThroughSequence = terminal.Sequence
		result.PrunedThroughTime = terminal.Timestamp
	} else if state.anchor != nil {
		result.PrunedThroughSequence = state.anchor.PrunedThroughSequence
		result.PrunedThroughTime = state.anchor.PrunedThroughTime
	}
	return result, nil
}

func (s *Store) estimatedPrunedBytes(project projectState, state chainState, cut int) (int64, error) {
	anchor, err := s.newAnchor(project, state.events[cut-1])
	if err != nil {
		return 0, err
	}
	encoded, err := json.Marshal(anchor)
	if err != nil {
		return 0, err
	}
	total := int64(len(encoded) + 1)
	for _, event := range state.events[cut:] {
		encoded, err := json.Marshal(event)
		if err != nil {
			return 0, err
		}
		total += int64(len(encoded) + 1)
	}
	if info, err := os.Stat(project.headPath); err == nil {
		total += info.Size()
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	return total, nil
}

func (s *Store) newAnchor(project projectState, terminal Event) (anchorRecord, error) {
	anchor := anchorRecord{
		Schema:                anchorSchemaV1,
		ProjectID:             project.id,
		PrunedThroughSequence: terminal.Sequence,
		PrunedThroughTime:     terminal.Timestamp,
		ChainMAC:              terminal.RecordMAC,
		CreatedAt:             s.now().UTC(),
	}
	var err error
	anchor.RecordMAC, err = signJSON(project.key, "ward-audit-anchor/v1", anchorWithoutMAC(anchor))
	if err != nil {
		return anchorRecord{}, fmt.Errorf("sign audit anchor: %w", err)
	}
	return anchor, nil
}

func projectAuditBytes(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var total int64
	for _, entry := range entries {
		_, _, segment := parseSegmentName(entry.Name())
		if !segment && entry.Name() != "head.json" {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return 0, errors.New("audit retention path must be a regular file")
		}
		info, err := entry.Info()
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}

func totalAuditBytes(projectsDir string) (int64, error) {
	entries, err := os.ReadDir(projectsDir)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, entry := range entries {
		if len(entry.Name()) != 64 || strings.Trim(entry.Name(), "0123456789abcdef") != "" {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			return 0, errors.New("project retention path must be a real directory")
		}
		bytes, err := projectAuditBytes(filepath.Join(projectsDir, entry.Name()))
		if err != nil {
			return 0, err
		}
		total += bytes
	}
	return total, nil
}

func (s *Store) existingProject(ctx context.Context, cwd string) (projectState, bool, error) {
	project, err := s.project(cwd)
	if err != nil {
		return projectState{}, false, err
	}
	catalog, err := s.verifyCatalog(ctx)
	if err != nil {
		return projectState{}, false, err
	}
	if !catalogHasProject(catalog, project.id) {
		return project, false, nil
	}
	info, err := os.Lstat(project.dir)
	if errors.Is(err, os.ErrNotExist) {
		return projectState{}, false, integrity(0, "missing_project_directory")
	}
	if err != nil {
		return projectState{}, false, fmt.Errorf("inspect project audit directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return projectState{}, false, errors.New("project audit path must be a real directory")
	}
	if err := inspectPrivateDirectoryPermissions(project.dir); err != nil {
		return projectState{}, false, fmt.Errorf("unsafe project audit permissions: %w", err)
	}
	return project, true, nil
}

func (s *Store) readLocked(ctx context.Context, project projectState) (chainState, error) {
	if err := s.lockContext(ctx); err != nil {
		return chainState{}, err
	}
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return chainState{}, err
	}
	lock, err := acquireFileLock(ctx, project.lockPath, lockShared, s.lockTimeout, false)
	if err != nil {
		return chainState{}, err
	}
	defer lock.release()
	return s.readVerifiedLogContext(ctx, project)
}
