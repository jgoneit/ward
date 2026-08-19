package evaluator

import "strings"

func (e *Evaluator) evaluatePatch(command, cwd string) scanResult {
	result := scanResult{}
	foundDirective := false
	for _, line := range strings.Split(command, "\n") {
		for _, prefix := range []string{
			"*** Add File:",
			"*** Update File:",
			"*** Delete File:",
			"*** Move to:",
		} {
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			foundDirective = true
			candidate := strings.TrimSpace(strings.TrimPrefix(line, prefix))
			if candidate == "" {
				result.addGap(gap("malformed_patch_path", "A patch file directive has no literal path."))
				continue
			}
			if isDynamicPath(candidate) {
				result.addGap(gap("dynamic_patch_path", "A patch file path contains unresolved expansion syntax."))
				continue
			}
			deleteOperation := prefix == "*** Delete File:"
			if ruleID, protected := e.matchProtectedPath(candidate, cwd, deleteOperation); protected {
				return denied(ruleID, secretReason)
			}
			if deleteOperation && isProtectedDeleteTarget(candidate) {
				return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
			}
		}
	}
	if !foundDirective {
		result.addGap(gap("unrecognized_patch", "The patch payload has no recognized file directive."))
	}
	return result
}
