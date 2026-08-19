package integration

import (
	"fmt"
	"path/filepath"
)

type controlPathSpec struct {
	id             string
	path           string
	require        bool
	allowRootOwner bool
}

func controlPathSpecs(paths Paths, requireManaged bool) []controlPathSpec {
	return []controlPathSpec{
		{id: "control.config", path: paths.ConfigFile, require: requireManaged},
		{id: "control.hooks", path: paths.HooksFile, require: requireManaged},
		{id: "control.binary", path: paths.BinaryPath, require: true, allowRootOwner: true},
	}
}

// validateControlPlane rejects authority paths that another local principal
// can replace. It never changes permissions: users must repair ownership,
// modes, ACLs, or symlinks explicitly before Ward installs or uninstalls.
func validateControlPlane(paths Paths, requireManaged bool) error {
	for _, spec := range controlPathSpecs(paths, requireManaged) {
		if err := inspectControlFile(spec.path, spec.require, spec.allowRootOwner); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrUnsafePath, spec.id, err)
		}
	}
	parents := map[string]struct{}{}
	for _, spec := range controlPathSpecs(paths, requireManaged) {
		parent := filepath.Clean(filepath.Dir(spec.path))
		if _, seen := parents[parent]; seen {
			continue
		}
		parents[parent] = struct{}{}
		if err := inspectControlParents(parent); err != nil {
			return fmt.Errorf("%w: control.parents for %s: %v", ErrUnsafePath, parent, err)
		}
	}
	return nil
}

func addControlPlaneChecks(report *DoctorReport, paths Paths) bool {
	add := reportAdder(report)
	healthy := true
	for _, spec := range controlPathSpecs(paths, true) {
		if err := inspectControlFile(spec.path, spec.require, spec.allowRootOwner); err != nil {
			add(spec.id, CheckFail, "Control file authority is unsafe: "+err.Error())
			healthy = false
		} else {
			add(spec.id, CheckPass, "Control file is regular, trusted-owned, and not writable by other principals.")
		}
	}
	parents := map[string]struct{}{}
	for _, spec := range controlPathSpecs(paths, true) {
		parent := filepath.Clean(filepath.Dir(spec.path))
		if _, seen := parents[parent]; seen {
			continue
		}
		parents[parent] = struct{}{}
		if err := inspectControlParents(parent); err != nil {
			add("control.parents", CheckFail, "Control path parent authority is unsafe: "+err.Error())
			healthy = false
			break
		}
	}
	if healthy {
		add("control.parents", CheckPass, "Control path parents are not replaceable by untrusted local principals.")
	}
	return healthy
}
