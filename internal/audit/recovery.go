package audit

import (
	"context"
	"errors"
	"fmt"
)

// RecoverHead explicitly advances a missing or stale signed head to a fully
// verified HMAC-chain tail. It never truncates records, rewinds a head, repairs
// malformed data, or runs implicitly from Record, Verify, or Doctor.
func (s *Store) RecoverHead(ctx context.Context, cwd string, dryRun bool) (RecoveryResult, error) {
	project, exists, err := s.existingProject(ctx, cwd)
	if err != nil {
		return RecoveryResult{}, err
	}
	result := RecoveryResult{ProjectID: project.id}
	if !exists {
		return result, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := acquireFileLock(ctx, project.lockPath, lockExclusive, s.lockTimeout, false)
	if err != nil {
		return RecoveryResult{}, err
	}
	defer lock.release()
	state, err := s.readVerifiedChain(project)
	if err != nil {
		return RecoveryResult{}, err
	}
	segments, err := listSegments(project.dir)
	if err != nil {
		return RecoveryResult{}, err
	}
	if len(segments) == 0 {
		if err := verifyHead(project, state, false); err != nil {
			return RecoveryResult{}, err
		}
		return result, nil
	}

	targetSequence := state.nextSequence() - 1
	targetMAC := state.lastMAC()
	head, headExists, err := readHead(project)
	if err != nil {
		return RecoveryResult{}, err
	}
	if headExists {
		result.FromSequence = head.LastSequence
		if head.LastSequence == targetSequence && head.LastMAC == targetMAC {
			return result, nil
		}
		if head.LastSequence >= targetSequence {
			return RecoveryResult{}, integrity(0, "head_recovery_not_forward")
		}
		prefixMAC, found := chainMACAtSequence(state, head.LastSequence)
		if !found || !verifyHexMAC(prefixMAC, head.LastMAC) {
			return RecoveryResult{}, integrity(0, "head_recovery_prefix_mismatch")
		}
	}
	if targetSequence == 0 || targetMAC == "" {
		return RecoveryResult{}, errors.New("verified audit tail is empty")
	}
	result.Needed = true
	result.ToSequence = targetSequence
	if dryRun {
		return result, nil
	}
	if err := writeHead(project, targetSequence, targetMAC, s.now().UTC()); err != nil {
		return RecoveryResult{}, fmt.Errorf("repair audit head: %w", err)
	}
	if _, err := s.readVerifiedLog(project); err != nil {
		return RecoveryResult{}, fmt.Errorf("verify repaired audit head: %w", err)
	}
	result.Repaired = true
	return result, nil
}

func chainMACAtSequence(state chainState, sequence uint64) (string, bool) {
	if state.anchor != nil && state.anchor.PrunedThroughSequence == sequence {
		return state.anchor.ChainMAC, true
	}
	for _, event := range state.events {
		if event.Sequence == sequence {
			return event.RecordMAC, true
		}
	}
	return "", false
}
