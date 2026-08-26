package evaluator

import (
	"errors"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

const maxGitParentWalk = 64

// BoundaryOptions contains trusted, process-local boundary inputs. Callers must
// pass Ward control and state paths explicitly; BoundarySet never exposes them
// again and must never be serialized or persisted.
type BoundaryOptions struct {
	CWD              string
	HomeDir          string
	WardControlPaths []string
	GOOS             string
}

// BoundarySet is an immutable, request-scoped set of catastrophic filesystem
// boundaries. Its fields are deliberately private so raw home, repository, and
// Ward control paths cannot accidentally enter a decision or diagnostic.
type BoundarySet struct {
	goos      string
	cwd       string
	home      string
	gitRoot   string
	gitPaths  []string
	roots     []string
	protected []string
	wardPaths []string
	valid     bool
}

// String and GoString keep accidental diagnostic formatting from exposing
// raw boundary paths. BoundarySet is process-local evaluator state, not data.
func (BoundarySet) String() string   { return "Ward BoundarySet(redacted)" }
func (BoundarySet) GoString() string { return "evaluator.BoundarySet{redacted}" }

// ResolveBoundarySet validates trusted boundary inputs and discovers the
// nearest Git root by a bounded parent walk. HomeDir defaults to the actual OS
// home directory; GOOS exists only to make cross-platform conformance tests
// deterministic and otherwise defaults to runtime.GOOS.
func ResolveBoundarySet(options BoundaryOptions) (BoundarySet, error) {
	goos := strings.ToLower(strings.TrimSpace(options.GOOS))
	if goos == "" {
		goos = runtime.GOOS
	}
	if goos != "darwin" && goos != "linux" && goos != "windows" {
		return BoundarySet{}, errors.New("unsupported boundary platform")
	}
	home := strings.TrimSpace(options.HomeDir)
	if home == "" {
		account, err := user.Current()
		if err != nil || strings.TrimSpace(account.HomeDir) == "" {
			return BoundarySet{}, errors.New("OS home directory is unavailable")
		}
		home = account.HomeDir
	}
	cwd, ok := normalizeAbsoluteBoundary(options.CWD, goos)
	if !ok {
		return BoundarySet{}, errors.New("request CWD must be an absolute literal path")
	}
	home, ok = normalizeAbsoluteBoundary(home, goos)
	if !ok {
		return BoundarySet{}, errors.New("OS home must be an absolute literal path")
	}

	wardPaths := make([]string, 0, len(options.WardControlPaths)*2)
	seenWard := map[string]struct{}{}
	for _, candidate := range options.WardControlPaths {
		normalized, valid := normalizeAbsoluteBoundary(candidate, goos)
		if !valid {
			return BoundarySet{}, errors.New("Ward control path must be an absolute literal path")
		}
		for _, alias := range trustedBoundaryAliases(normalized, goos) {
			if _, exists := seenWard[alias]; exists {
				continue
			}
			seenWard[alias] = struct{}{}
			wardPaths = append(wardPaths, alias)
		}
	}

	roots := boundaryRoots(goos, append([]string{cwd, home}, wardPaths...))
	if len(roots) == 0 {
		return BoundarySet{}, errors.New("filesystem root could not be resolved")
	}
	gitRoot := discoverNearestGitRoot(cwd, goos)
	protected := make([]string, 0, 6)
	seenProtected := map[string]struct{}{}
	for _, candidate := range []string{cwd, home, gitRoot} {
		for _, alias := range trustedBoundaryAliases(candidate, goos) {
			if alias == "" {
				continue
			}
			if _, exists := seenProtected[alias]; exists {
				continue
			}
			seenProtected[alias] = struct{}{}
			protected = append(protected, alias)
		}
	}
	gitPaths := make([]string, 0, 2)
	seenGitPaths := map[string]struct{}{}
	if gitRoot != "" {
		for _, alias := range trustedBoundaryAliases(path.Join(gitRoot, ".git"), goos) {
			if alias == "" {
				continue
			}
			if _, exists := seenGitPaths[alias]; exists {
				continue
			}
			seenGitPaths[alias] = struct{}{}
			gitPaths = append(gitPaths, alias)
		}
	}
	return BoundarySet{
		goos:      goos,
		cwd:       cwd,
		home:      home,
		gitRoot:   gitRoot,
		gitPaths:  gitPaths,
		roots:     roots,
		protected: protected,
		wardPaths: wardPaths,
		valid:     true,
	}, nil
}

func (b BoundarySet) validFor(cwd string) bool {
	if !b.valid || b.cwd == "" || b.home == "" || len(b.roots) == 0 {
		return false
	}
	normalized, ok := normalizeAbsoluteBoundary(cwd, b.goos)
	return ok && b.sameBoundaryObject(normalized, b.cwd)
}

func normalizeAbsoluteBoundary(value, goos string) (string, bool) {
	value = strings.TrimSpace(strings.ReplaceAll(value, `\`, "/"))
	if value == "" || strings.ContainsAny(value, "\x00\r\n") || strings.ContainsAny(value, "$%*?[]{}\x60") {
		return "", false
	}
	extendedWindowsPath := false
	if goos == "windows" {
		lower := strings.ToLower(value)
		switch {
		case strings.HasPrefix(lower, "//?/unc/"):
			value = "//" + value[len("//?/unc/"):]
			extendedWindowsPath = true
		case strings.HasPrefix(lower, "//?/"):
			value = value[len("//?/"):]
			extendedWindowsPath = true
		case strings.HasPrefix(lower, "//./"):
			return "", false
		}
	}
	windowsAbsolute := isWindowsAbsolutePath(value)
	if goos == "windows" {
		if !windowsAbsolute {
			return "", false
		}
	} else if !path.IsAbs(value) {
		return "", false
	}
	if goos == "windows" {
		if !extendedWindowsPath {
			value = normalizeWin32PathComponents(value)
		}
		value = path.Clean(value)
		value = strings.ToLower(value)
		if len(value) == 2 && value[1] == ':' {
			value += "/"
		}
	}
	value = path.Clean(value)
	return value, true
}

func normalizeWin32PathComponents(value string) string {
	root := ""
	rest := ""
	if len(value) >= 3 && value[1] == ':' && value[2] == '/' {
		root, rest = value[:3], value[3:]
	} else if strings.HasPrefix(value, "//") {
		parts := strings.Split(strings.TrimPrefix(value, "//"), "/")
		if len(parts) < 2 {
			return value
		}
		root = "//" + parts[0] + "/" + parts[1]
		rest = strings.Join(parts[2:], "/")
	} else {
		return value
	}
	parts := strings.Split(rest, "/")
	for index, component := range parts {
		withoutSpaces := strings.TrimRight(component, " ")
		if withoutSpaces == "." || withoutSpaces == ".." {
			parts[index] = withoutSpaces
			continue
		}
		component = strings.TrimRight(withoutSpaces, ".")
		if component == "" {
			component = "."
		}
		parts[index] = component
	}
	if rest == "" {
		return root
	}
	return root + "/" + strings.Join(parts, "/")
}

func trustedBoundaryAliases(candidate, goos string) []string {
	if candidate == "" {
		return nil
	}
	aliases := []string{candidate}
	if goos != runtime.GOOS {
		return aliases
	}
	resolved, err := filepath.EvalSymlinks(filepath.FromSlash(candidate))
	if err != nil {
		return aliases
	}
	normalized, ok := normalizeAbsoluteBoundary(filepath.ToSlash(resolved), goos)
	if ok && !sameBoundaryPath(normalized, candidate, goos) {
		aliases = append(aliases, normalized)
	}
	return aliases
}

func boundaryRoots(goos string, candidates []string) []string {
	if goos != "windows" {
		return []string{"/"}
	}
	seen := map[string]struct{}{}
	var roots []string
	for _, candidate := range candidates {
		root := windowsBoundaryRoot(candidate)
		if root == "" {
			continue
		}
		if _, exists := seen[root]; exists {
			continue
		}
		seen[root] = struct{}{}
		roots = append(roots, root)
	}
	return roots
}

func windowsBoundaryRoot(value string) string {
	value = strings.ToLower(strings.ReplaceAll(value, `\`, "/"))
	if len(value) >= 2 && value[1] == ':' {
		return value[:2] + "/"
	}
	if strings.HasPrefix(value, "//") {
		parts := strings.Split(strings.TrimPrefix(value, "//"), "/")
		if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
			return "//" + parts[0] + "/" + parts[1]
		}
	}
	return ""
}

func discoverNearestGitRoot(cwd, goos string) string {
	// Cross-platform fixtures may contain paths the running OS cannot inspect.
	if goos != runtime.GOOS || goos == "windows" && !isWindowsAbsolutePath(cwd) {
		return ""
	}
	current := cwd
	for depth := 0; depth < maxGitParentWalk; depth++ {
		if info, err := os.Lstat(path.Join(current, ".git")); err == nil && (info.IsDir() || info.Mode().IsRegular()) {
			return current
		}
		parent := path.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return ""
}

func (b BoundarySet) resolve(candidate string) (string, bool) {
	value := strings.TrimSpace(strings.ReplaceAll(candidate, `\`, "/"))
	if value == "" || strings.ContainsAny(value, "\x00\r\n") || isDynamicPath(value) || value == "~" || strings.HasPrefix(value, "~/") {
		return "", false
	}
	if b.goos == "windows" {
		if isWindowsAbsolutePath(value) {
			return normalizeAbsoluteBoundary(value, b.goos)
		}
		// A single leading slash or backslash is rooted at the current Windows
		// drive (or UNC share), not at an ambiguous POSIX root. Resolve it from
		// the trusted request CWD so literal PowerShell/CMD root deletion cannot
		// evade the filesystem boundary.
		if strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") {
			root := windowsBoundaryRoot(b.cwd)
			if root == "" {
				return "", false
			}
			relative := strings.TrimLeft(value, "/")
			if relative == "" {
				return normalizeAbsoluteBoundary(root, b.goos)
			}
			return normalizeAbsoluteBoundary(path.Join(root, relative), b.goos)
		}
		if path.IsAbs(value) || len(value) >= 2 && value[1] == ':' {
			return "", false
		}
	} else if path.IsAbs(value) {
		return normalizeAbsoluteBoundary(value, b.goos)
	}
	return normalizeAbsoluteBoundary(path.Join(b.cwd, value), b.goos)
}

func (b BoundarySet) resolveKnownDirectory(base, candidate string) (string, bool) {
	value := strings.TrimSpace(strings.ReplaceAll(candidate, `\`, "/"))
	if value == "" || isDynamicPath(value) {
		return "", false
	}
	var target string
	if b.isAbsoluteCandidate(value) {
		target = value
	} else {
		normalizedBase, ok := normalizeAbsoluteBoundary(base, b.goos)
		if !ok {
			return "", false
		}
		target = path.Join(normalizedBase, value)
	}
	normalized, ok := normalizeAbsoluteBoundary(target, b.goos)
	if !ok {
		return "", false
	}
	if b.goos != runtime.GOOS {
		return normalized, true
	}
	for _, known := range append(append([]string{}, b.protected...), b.roots...) {
		if sameBoundaryPath(normalized, known, b.goos) {
			return normalized, true
		}
	}
	resolved, err := filepath.EvalSymlinks(filepath.FromSlash(normalized))
	if err != nil {
		return "", false
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", false
	}
	return normalizeAbsoluteBoundary(filepath.ToSlash(resolved), b.goos)
}

func (b BoundarySet) isAbsoluteCandidate(candidate string) bool {
	value := strings.TrimSpace(strings.ReplaceAll(candidate, `\`, "/"))
	if b.goos == "windows" {
		return isWindowsAbsolutePath(value)
	}
	return path.IsAbs(value)
}

// protectsCriticalMetadata reports whether a non-recursive delete directly
// targets Git metadata or Ward's own control boundary.
// General filesystem roots, HOME, CWD, and repository roots are deliberately
// excluded here: Ward only vetoes those targets when the operation is known to
// recurse.
func (b BoundarySet) protectsCriticalMetadata(candidate string) bool {
	for _, target := range b.candidateAliases(candidate, false) {
		if containsDotGitComponent(target, b.goos) || b.targetsGitPath(target, false) || b.targetsWardPath(target, false) {
			return true
		}
	}
	return false
}

// protectsCriticalRelocation also includes an ancestor whose relocation would
// carry Ward control or state paths with it.
func (b BoundarySet) protectsCriticalRelocation(candidate string) bool {
	for _, target := range b.candidateAliases(candidate, false) {
		// Moving Git metadata itself removes it from the repository and remains
		// protected, but moving an ordinary directory that merely contains a
		// repository is a Host-controlled, recoverable operation. Ward control
		// and state anchors are the only paths whose ancestors are relocation
		// boundaries.
		if containsDotGitComponent(target, b.goos) || b.targetsGitPath(target, false) || b.overlapsWardPath(target, false) {
			return true
		}
	}
	return false
}

// protectsRecursiveDelete reports whether a recursive tree deletion can
// remove a catastrophic boundary. Descendants of HOME/CWD/repository roots are
// ordinary cleanup targets and are not protected by this method.
func (b BoundarySet) protectsRecursiveDelete(candidate string) bool {
	return b.protectsRecursiveDeleteWithAliases(b.candidateAliases(candidate, false), false)
}

func (b BoundarySet) protectsDereferencedRecursiveDelete(candidate string) bool {
	return b.protectsRecursiveDeleteWithAliases(b.candidateAliases(candidate, true), true)
}

func (b BoundarySet) protectsRecursiveDeleteWithAliases(targets []string, dereferenceLeaf bool) bool {
	for _, target := range targets {
		if target == "/" || b.goos == "windows" && sameBoundaryPath(target, windowsBoundaryRoot(target), b.goos) {
			return true
		}
		if containsDotGitComponent(target, b.goos) || b.overlapsGitPath(target, dereferenceLeaf) || b.overlapsWardPath(target, dereferenceLeaf) {
			return true
		}
		for _, protected := range append(append([]string{}, b.protected...), b.roots...) {
			if protected != "" && (b.sameBoundaryObjectForOperation(target, protected, dereferenceLeaf) || b.boundaryObjectContainsForOperation(target, protected, dereferenceLeaf)) {
				return true
			}
		}
	}
	return false
}

func (b BoundarySet) protectsParentRemoval(candidate string) bool {
	targets := b.candidateAliases(candidate, false)
	if b.protectsRecursiveDeleteWithAliases(targets, false) {
		return true
	}
	for _, target := range targets {
		for _, protected := range b.protected {
			if protected != "" && b.boundaryObjectContainsForOperation(protected, target, false) {
				return true
			}
		}
	}
	return false
}

func (b BoundarySet) candidateAliases(candidate string, dereferenceLeaf bool) []string {
	target, ok := b.resolve(candidate)
	if !ok {
		return nil
	}
	aliases := []string{target}
	if b.goos != runtime.GOOS {
		return aliases
	}
	resolveTarget := target
	if !dereferenceLeaf {
		resolveTarget = path.Dir(target)
	}
	resolved, err := filepath.EvalSymlinks(filepath.FromSlash(resolveTarget))
	if err != nil {
		return aliases
	}
	resolvedValue := filepath.ToSlash(resolved)
	if !dereferenceLeaf {
		resolvedValue = path.Join(resolvedValue, path.Base(target))
	}
	normalized, valid := normalizeAbsoluteBoundary(resolvedValue, b.goos)
	if valid {
		for _, existing := range aliases {
			if sameBoundaryPath(existing, normalized, b.goos) {
				return aliases
			}
		}
		aliases = append(aliases, normalized)
	}
	return aliases
}

func (b BoundarySet) overlapsWardPath(target string, dereferenceLeaf bool) bool {
	for _, protected := range b.wardPaths {
		if b.sameBoundaryObjectForOperation(target, protected, dereferenceLeaf) || b.boundaryObjectContainsForOperation(target, protected, dereferenceLeaf) || b.boundaryObjectContainsForOperation(protected, target, dereferenceLeaf) {
			return true
		}
	}
	return false
}

func (b BoundarySet) targetsWardPath(target string, dereferenceLeaf bool) bool {
	for _, protected := range b.wardPaths {
		if b.sameBoundaryObjectForOperation(target, protected, dereferenceLeaf) || b.boundaryObjectContainsForOperation(protected, target, dereferenceLeaf) {
			return true
		}
	}
	return false
}

func (b BoundarySet) overlapsGitPath(target string, dereferenceLeaf bool) bool {
	for _, protected := range b.gitPaths {
		if b.sameBoundaryObjectForOperation(target, protected, dereferenceLeaf) || b.boundaryObjectContainsForOperation(target, protected, dereferenceLeaf) || b.boundaryObjectContainsForOperation(protected, target, dereferenceLeaf) {
			return true
		}
	}
	return false
}

func (b BoundarySet) targetsGitPath(target string, dereferenceLeaf bool) bool {
	for _, protected := range b.gitPaths {
		if b.sameBoundaryObjectForOperation(target, protected, dereferenceLeaf) || b.boundaryObjectContainsForOperation(protected, target, dereferenceLeaf) {
			return true
		}
	}
	return false
}

// sameBoundaryObjectForOperation keeps physical delete and relocation
// semantics distinct from commands such as find -H that explicitly follow a
// command-line symlink. Lstat prevents an ordinary rm -rf or mv of a symlink
// from being promoted to an operation on the symlink's target.
func (b BoundarySet) sameBoundaryObjectForOperation(left, right string, dereferenceLeaf bool) bool {
	if dereferenceLeaf {
		return b.sameBoundaryObject(left, right)
	}
	if sameBoundaryPath(left, right, b.goos) {
		return true
	}
	if b.goos != runtime.GOOS {
		return false
	}
	leftInfo, leftErr := os.Lstat(filepath.FromSlash(left))
	rightInfo, rightErr := os.Lstat(filepath.FromSlash(right))
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo)
}

func (b BoundarySet) boundaryObjectContainsForOperation(parent, child string, dereferenceLeaf bool) bool {
	if boundaryContains(parent, child, b.goos) {
		return true
	}
	if b.goos != runtime.GOOS {
		return false
	}
	current := path.Clean(child)
	for depth := 0; depth < maxGitParentWalk+8; depth++ {
		if b.sameBoundaryObjectForOperation(parent, current, dereferenceLeaf) {
			return true
		}
		next := path.Dir(current)
		if next == current {
			break
		}
		current = next
	}
	return false
}

// sameBoundaryObject extends lexical comparison only when both paths exist on
// the running filesystem. This catches case-preserving aliases on default
// macOS volumes without pretending that every Darwin filesystem is
// case-insensitive or changing synthetic cross-platform fixtures.
func (b BoundarySet) sameBoundaryObject(left, right string) bool {
	if sameBoundaryPath(left, right, b.goos) {
		return true
	}
	if b.goos != runtime.GOOS {
		return false
	}
	leftInfo, leftErr := os.Stat(filepath.FromSlash(left))
	rightInfo, rightErr := os.Stat(filepath.FromSlash(right))
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo)
}

// boundaryObjectContains is the existing-object equivalent of
// boundaryContains. Walking the child upward lets inode identity recognize a
// differently-cased or symlinked parent while retaining lexical behavior for
// paths that do not exist yet.
func (b BoundarySet) boundaryObjectContains(parent, child string) bool {
	if boundaryContains(parent, child, b.goos) {
		return true
	}
	if b.goos != runtime.GOOS {
		return false
	}
	current := path.Clean(child)
	for depth := 0; depth < maxGitParentWalk+8; depth++ {
		if b.sameBoundaryObject(parent, current) {
			return true
		}
		next := path.Dir(current)
		if next == current {
			break
		}
		current = next
	}
	return false
}

func sameBoundaryPath(left, right, goos string) bool {
	if goos == "windows" {
		return strings.EqualFold(strings.TrimSuffix(left, "/"), strings.TrimSuffix(right, "/"))
	}
	return path.Clean(left) == path.Clean(right)
}

func boundaryContains(parent, child, goos string) bool {
	parent = strings.TrimSuffix(path.Clean(parent), "/")
	child = strings.TrimSuffix(path.Clean(child), "/")
	if parent == "" {
		parent = "/"
	}
	if goos == "windows" {
		parent, child = strings.ToLower(parent), strings.ToLower(child)
	}
	return child == parent || parent == "/" && strings.HasPrefix(child, "/") || strings.HasPrefix(child, parent+"/")
}

func containsDotGitComponent(value, goos string) bool {
	for _, component := range strings.Split(strings.Trim(value, "/"), "/") {
		if component == ".git" || goos == "windows" && strings.EqualFold(component, ".git") {
			return true
		}
	}
	return false
}
