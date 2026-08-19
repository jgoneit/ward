package evaluator

import (
	"path"
	"strings"
	"unicode"
)

func (e *Evaluator) evaluatePowerShell(command, cwd string) scanResult {
	if windowsCompoundInteractiveTail(command, true) {
		return denied("WARD_INTERACTIVE_SESSION", "An explicit interactive session is denied.")
	}
	argv, ok := splitLiteralWindows(command, true)
	if !ok {
		return scanResult{gap: gap("ambiguous_powershell", "PowerShell input is not a high-confidence literal command.")}
	}
	if inputDrivenWindowsInteractive(argv) {
		return denied("WARD_INTERACTIVE_SESSION", "An explicit interactive session is denied.")
	}
	return e.evaluateWindowsArgv(argv, cwd, true)
}

func (e *Evaluator) evaluateCMD(command, cwd string) scanResult {
	if windowsCompoundInteractiveTail(command, false) {
		return denied("WARD_INTERACTIVE_SESSION", "An explicit interactive session is denied.")
	}
	if exactCMDHelp(command) {
		return scanResult{}
	}
	argv, ok := splitLiteralWindows(command, false)
	if !ok {
		return scanResult{gap: gap("ambiguous_cmd", "Cmd input is not a high-confidence literal command.")}
	}
	if inputDrivenWindowsInteractive(argv) {
		return denied("WARD_INTERACTIVE_SESSION", "An explicit interactive session is denied.")
	}
	if len(argv) >= 3 && executableBase(argv[0]) == "cmd" && strings.EqualFold(argv[1], "/c") {
		argv = argv[2:]
	}
	return e.evaluateWindowsArgv(argv, cwd, false)
}

func windowsCompoundInteractiveTail(command string, powershell bool) bool {
	if strings.ContainsAny(command, "\r\n\x00") || powershell && strings.Contains(command, "`") ||
		!powershell && strings.Contains(command, "^") {
		return false
	}
	separator := '&'
	if powershell {
		separator = ';'
	}
	quote := rune(0)
	last := -1
	for index, char := range command {
		if quote != 0 {
			if char == quote {
				quote = 0
			}
			continue
		}
		if char == '"' || powershell && char == '\'' {
			quote = char
			continue
		}
		if char == separator {
			last = index
		}
	}
	if quote != 0 || last < 0 || last+1 >= len(command) {
		return false
	}
	tail := strings.TrimSpace(command[last+1:])
	argv, ok := splitLiteralWindows(tail, powershell)
	return ok && inputDrivenWindowsInteractive(argv)
}

func exactCMDHelp(command string) bool {
	fields := strings.Fields(command)
	return len(fields) == 2 && executableBase(fields[0]) == "cmd" && strings.EqualFold(fields[1], "/?")
}

func inputDrivenWindowsInteractive(values []string) bool {
	argv := make([]literalArg, len(values))
	for index, value := range values {
		argv[index] = literalArg{value: value, static: true}
	}
	if len(argv) > 0 {
		argv[0].value = executableBase(argv[0].value)
	}
	if inputDrivenInteractive(argv) {
		return true
	}
	if len(values) < 2 {
		return false
	}
	switch executableBase(values[0]) {
	case "powershell", "pwsh":
		for _, value := range values[1:] {
			switch strings.ToLower(value) {
			case "-nologo", "-noprofile", "-noexit":
				continue
			default:
				return false
			}
		}
		return true
	case "cmd":
		for _, value := range values[1:] {
			switch strings.ToLower(value) {
			case "/q", "/d", "/a", "/u", "/e:on", "/e:off", "/f:on", "/f:off", "/v:on", "/v:off":
				continue
			default:
				return false
			}
		}
		return true
	default:
		return false
	}
}

func (e *Evaluator) evaluateWindowsArgv(values []string, cwd string, powershell bool) scanResult {
	if len(values) == 0 {
		return scanResult{gap: gap("empty_windows_command", "The Windows command contains no literal executable.")}
	}
	argv := make([]literalArg, len(values))
	for i, value := range values {
		argv[i] = literalArg{value: value, static: true}
	}
	base := executableBase(argv[0].value)
	result := scanResult{}
	if ruleID, matched, _ := e.matchAdditiveCommand(argv, true); matched {
		return denied(ruleID, additiveReason)
	}

	fileCommand := false
	deleteCommand := false
	moveCommand := false
	if powershell {
		switch base {
		case "get-content", "gc", "type", "copy-item", "cp", "move-item", "mv", "remove-item", "rm", "ri", "clear-content":
			fileCommand = true
		}
		deleteCommand = base == "remove-item" || base == "rm" || base == "ri"
		moveCommand = base == "move-item" || base == "mv"
	} else {
		switch base {
		case "type", "copy", "move", "del", "erase", "rd", "rmdir":
			fileCommand = true
		}
		deleteCommand = base == "del" || base == "erase" || base == "rd" || base == "rmdir"
		moveCommand = base == "move"
	}
	fileOperands := values[1:]
	if fileCommand {
		if powershell {
			var ambiguous bool
			fileOperands, ambiguous = powerShellFileOperands(values[1:])
			if ambiguous {
				result.addGap(gap("ambiguous_powershell_options", "PowerShell file-command options are outside Ward classification."))
			}
		} else {
			fileOperands = cmdFileOperands(values[1:])
		}
		for index, value := range fileOperands {
			if strings.HasPrefix(value, "-") || strings.HasPrefix(value, "/") && len(value) <= 3 {
				continue
			}
			var ruleID string
			var protected bool
			moveSource := moveCommand && index < len(fileOperands)-1
			ruleID, protected = e.matchProtectedPath(value, cwd, deleteCommand || moveSource)
			if protected {
				return denied(ruleID, secretReason)
			}
			if deleteCommand && isProtectedDeleteTarget(value) {
				return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
			}
		}
	}
	operationArgs, operationGap := unwrapOperationGlobalOptions(base, argv[1:])
	result.addGap(operationGap)

	if powershell && (base == "remove-item" || base == "rm" || base == "ri") {
		recursive := hasFold(values[1:], "-recurse") || hasFold(values[1:], "-r")
		if recursive && hasCatastrophicWindowsTarget(fileOperands, cwd) {
			return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
		}
	}
	if !powershell && (base == "del" || base == "erase" || base == "rd" || base == "rmdir") {
		recursive := hasFold(values[1:], "/s")
		if recursive && hasCatastrophicWindowsTarget(fileOperands, cwd) {
			return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
		}
	}

	// Git, database, and infrastructure subcommands have identical literal
	// argv semantics once Windows shell expansion has been ruled out.
	switch base {
	case "git":
		if literalAt(operationArgs, 0, "rm") {
			deleteResult := e.evaluateDeleteTargets(operationArgs[1:], cwd)
			if deleteResult.deny != nil {
				return deleteResult
			}
		}
		if destructiveGit(operationArgs) {
			return denied("WARD_DESTRUCTIVE_GIT", destructiveGitReason)
		}
	case "terraform":
		if destructiveTerraform(operationArgs) {
			return denied("WARD_DESTRUCTIVE_INFRASTRUCTURE", destructiveOpsReason)
		}
	case "kubectl":
		destructive, kubectlGap := destructiveKubectl(operationArgs)
		result.addGap(kubectlGap)
		if destructive {
			return denied("WARD_DESTRUCTIVE_INFRASTRUCTURE", destructiveOpsReason)
		}
	case "docker":
		destructive, composeGap := destructiveDocker(operationArgs)
		result.addGap(composeGap)
		if destructive {
			return denied("WARD_DESTRUCTIVE_INFRASTRUCTURE", destructiveOpsReason)
		}
	case "docker-compose":
		destructive, composeGap := destructiveCompose(operationArgs)
		result.addGap(composeGap)
		if destructive {
			return denied("WARD_DESTRUCTIVE_INFRASTRUCTURE", destructiveOpsReason)
		}
	}
	if containsDestructiveSQL(base, argv[1:]) {
		return denied("WARD_DESTRUCTIVE_DATABASE", destructiveDBReason)
	}
	return result
}

func powerShellFileOperands(values []string) ([]string, bool) {
	operands := make([]string, 0, len(values))
	for i := 0; i < len(values); i++ {
		value := values[i]
		if !strings.HasPrefix(value, "-") {
			operands = append(operands, value)
			continue
		}
		switch strings.ToLower(value) {
		case "-path", "-literalpath", "-destination":
			if i+1 >= len(values) || strings.HasPrefix(values[i+1], "-") {
				return operands, true
			}
			i++
			operands = append(operands, values[i])
		case "-raw", "-wait", "-force", "-recurse", "-r", "-confirm", "-whatif", "-passthru", "-container":
			continue
		case "-filter", "-include", "-exclude", "-encoding", "-readcount", "-totalcount", "-tail", "-stream", "-credential", "-erroraction", "-warningaction", "-informationaction":
			if i+1 >= len(values) || strings.HasPrefix(values[i+1], "-") {
				return operands, true
			}
			i++
		default:
			return operands, true
		}
	}
	return operands, false
}

func cmdFileOperands(values []string) []string {
	operands := make([]string, 0, len(values))
	for _, value := range values {
		if strings.HasPrefix(value, "/") && len(value) <= 5 {
			continue
		}
		operands = append(operands, value)
	}
	return operands
}

func splitLiteralWindows(command string, powershell bool) ([]string, bool) {
	if strings.TrimSpace(command) == "" || strings.ContainsAny(command, "\r\n\x00") {
		return nil, false
	}
	if strings.ContainsAny(command, "&|<>;,`$(){}*?[]") {
		return nil, false
	}
	if !powershell && strings.ContainsAny(command, "%!^") {
		return nil, false
	}

	var words []string
	var current strings.Builder
	var quote rune
	wordStarted := false
	flush := func() {
		if wordStarted {
			words = append(words, current.String())
			current.Reset()
			wordStarted = false
		}
	}
	for _, char := range command {
		if quote != 0 {
			if char == quote {
				quote = 0
				continue
			}
			current.WriteRune(char)
			wordStarted = true
			continue
		}
		if char == '"' || powershell && char == '\'' {
			quote = char
			wordStarted = true
			continue
		}
		if unicode.IsSpace(char) {
			flush()
			continue
		}
		current.WriteRune(char)
		wordStarted = true
	}
	if quote != 0 {
		return nil, false
	}
	flush()
	return words, len(words) > 0
}

func hasFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

func hasCatastrophicWindowsTarget(values []string, cwd string) bool {
	normalizedCWD := strings.ToLower(strings.TrimSuffix(strings.ReplaceAll(cwd, `\`, "/"), "/"))
	for _, value := range values {
		if strings.HasPrefix(value, "-") || strings.HasPrefix(value, "/") && len(value) <= 3 {
			continue
		}
		normalized := strings.ToLower(strings.TrimSuffix(strings.ReplaceAll(value, `\`, "/"), "/"))
		if normalized == "." || normalized == ".." || normalized == "*" || normalized == ".git" || normalized == normalizedCWD {
			return true
		}
		if len(normalized) == 2 && normalized[1] == ':' || len(normalized) == 3 && normalized[1:] == ":/" {
			return true
		}
		cleaned := path.Clean(normalized)
		if isProtectedDeleteTarget(cleaned) || isCommonHomeRoot(cleaned) {
			return true
		}
		if isWindowsAbsolutePath(cleaned) && !isCleanupTarget(cleaned) &&
			(!windowsPathWithin(cleaned, normalizedCWD) || windowsPathWithin(normalizedCWD, cleaned)) {
			return true
		}
	}
	return false
}

func isWindowsAbsolutePath(value string) bool {
	return len(value) >= 3 && value[1] == ':' && value[2] == '/' || strings.HasPrefix(value, "//")
}

func windowsPathWithin(candidate, root string) bool {
	candidate = strings.TrimSuffix(path.Clean(candidate), "/")
	root = strings.TrimSuffix(path.Clean(root), "/")
	return strings.EqualFold(candidate, root) || strings.HasPrefix(strings.ToLower(candidate), strings.ToLower(root)+"/")
}
