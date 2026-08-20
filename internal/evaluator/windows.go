package evaluator

import (
	"path"
	"strings"
	"unicode"
)

const maxNestedWindowsShellDepth = 3

func (e *Evaluator) evaluatePowerShell(command, cwd string) scanResult {
	return e.evaluatePowerShellDepth(command, cwd, 0)
}

func (e *Evaluator) evaluatePowerShellDepth(command, cwd string, depth int) scanResult {
	if depth > maxNestedWindowsShellDepth {
		return scanResult{gap: gap("nested_shell_limit", "Nested shell evaluation exceeded its bounded depth.")}
	}
	statements, ok := splitLiteralWindowsStatements(command, true)
	if !ok {
		return scanResult{gap: gap("ambiguous_powershell", "PowerShell input is not a high-confidence literal command.")}
	}
	result := scanResult{}
	for _, statement := range statements {
		statement = trimPowerShellCallOperator(statement)
		argv, literal := splitLiteralWindows(statement, true)
		if !literal {
			result.addGap(gap("ambiguous_powershell", "PowerShell input is not a high-confidence literal command."))
			continue
		}
		if script, nested := reviewedPowerShellCommandPayload(argv); nested {
			result.merge(e.evaluatePowerShellDepth(script, cwd, depth+1))
		} else if script, nested := reviewedCMDCommandPayload(argv); nested {
			result.merge(e.evaluateCMDDepth(script, cwd, depth+1))
		} else {
			result.merge(e.evaluateWindowsArgv(argv, cwd, true))
		}
		if result.deny != nil {
			return result
		}
	}
	return result
}

func (e *Evaluator) evaluateCMD(command, cwd string) scanResult {
	return e.evaluateCMDDepth(command, cwd, 0)
}

func (e *Evaluator) evaluateCMDDepth(command, cwd string, depth int) scanResult {
	if depth > maxNestedWindowsShellDepth {
		return scanResult{gap: gap("nested_shell_limit", "Nested shell evaluation exceeded its bounded depth.")}
	}
	if exactCMDHelp(command) {
		return scanResult{}
	}
	statements, ok := splitLiteralWindowsStatements(command, false)
	if !ok {
		return scanResult{gap: gap("ambiguous_cmd", "Cmd input is not a high-confidence literal command.")}
	}
	result := scanResult{}
	for _, statement := range statements {
		words, literal := splitLiteralWindowsWords(statement, false)
		if !literal {
			result.addGap(gap("ambiguous_cmd", "Cmd input is not a high-confidence literal command."))
			continue
		}
		argv := windowsLiteralWordValues(words)
		if script, nested := reviewedCMDWrapperPayload(words); nested {
			result.merge(e.evaluateCMDDepth(script, cwd, depth+1))
		} else if script, nested := reviewedCMDCommandPayload(argv); nested {
			result.merge(e.evaluateCMDDepth(script, cwd, depth+1))
		} else if script, nested := reviewedPowerShellCommandPayload(argv); nested {
			result.merge(e.evaluatePowerShellDepth(script, cwd, depth+1))
		} else {
			result.merge(e.evaluateWindowsArgv(argv, cwd, false))
		}
		if result.deny != nil {
			return result
		}
	}
	return result
}

func exactCMDHelp(command string) bool {
	fields := strings.Fields(command)
	return len(fields) == 2 && executableBase(fields[0]) == "cmd" && strings.EqualFold(fields[1], "/?")
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
	fileCommand := false
	deleteCommand := false
	moveCommand := false
	if powershell {
		switch base {
		case "get-content", "gc", "type", "copy-item", "cp", "move-item", "mv", "mi", "move",
			"remove-item", "rm", "ri", "del", "erase", "rd", "rmdir", "clear-content":
			fileCommand = true
		}
		deleteCommand = base == "remove-item" || base == "rm" || base == "ri" || base == "del" || base == "erase" || base == "rd" || base == "rmdir"
		moveCommand = base == "move-item" || base == "mv" || base == "mi" || base == "move"
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
		if powershell && powerShellWhatIf(values[1:]) || !powershell && cmdFileInformational(values[1:]) {
			return result
		}
		if powershell {
			var ambiguous, narrowing bool
			fileOperands, ambiguous, narrowing = powerShellFileOperands(values[1:])
			if ambiguous {
				result.addGap(gap("ambiguous_powershell_options", "PowerShell file-command options are outside Ward classification."))
			}
			if narrowing {
				result.addGap(gap("ambiguous_powershell_options", "A PowerShell provider selector narrows the file operation."))
				return result
			}
		} else {
			fileOperands = cmdFileOperands(values[1:])
		}
		if powershell {
			for index := range fileOperands {
				fileOperands[index] = e.normalizePowerShellFileOperand(fileOperands[index])
			}
		}
		for index, value := range fileOperands {
			if strings.HasPrefix(value, "-") || !powershell && strings.HasPrefix(value, "/") && len(value) <= 3 {
				continue
			}
			moveSource := moveCommand && index < len(fileOperands)-1
			if deleteCommand && e.boundaries.protectsCriticalMetadata(value) || moveSource && e.boundaries.protectsCriticalRelocation(value) {
				return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
			}
		}
	}
	operationArgs, operationGap := unwrapOperationGlobalOptions(base, argv[1:])
	result.addGap(operationGap)

	if powershell && deleteCommand {
		recursive := powerShellRecursive(values[1:])
		if recursive && e.hasCatastrophicWindowsTarget(fileOperands) {
			return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
		}
	}
	if !powershell && (base == "del" || base == "erase" || base == "rd" || base == "rmdir") {
		recursive := hasFold(values[1:], "/s")
		if recursive && e.hasCatastrophicWindowsTarget(fileOperands) {
			return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
		}
	}

	// Git, database, and infrastructure subcommands have identical literal
	// argv semantics once Windows shell expansion has been ruled out.
	switch base {
	case "git":
		if literalAt(operationArgs, 0, "rm") {
			if gitSubcommandDryRun(operationArgs[1:]) {
				return result
			}
			deleteResult := e.evaluateDeleteTargets(operationArgs[1:], cwd, false)
			if deleteResult.deny != nil {
				return deleteResult
			}
		}
		if literalAt(operationArgs, 0, "mv") {
			if gitSubcommandDryRun(operationArgs[1:]) {
				return result
			}
			moveResult := e.evaluateMoveAncestors(operationArgs[1:], cwd, false)
			if moveResult.deny != nil {
				return moveResult
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

func powerShellWhatIf(values []string) bool {
	for _, value := range values {
		if strings.EqualFold(value, "-whatif") || strings.EqualFold(value, "-whatif:$true") {
			return true
		}
	}
	return false
}

func powerShellRecursive(values []string) bool {
	for _, value := range values {
		switch strings.ToLower(value) {
		case "-recurse", "-r", "-rec", "-recurse:$true", "-r:$true", "-rec:$true":
			return true
		}
	}
	return false
}

func cmdFileInformational(values []string) bool {
	for _, value := range values {
		if strings.EqualFold(value, "/?") {
			return true
		}
	}
	return false
}

func powerShellFileOperands(values []string) ([]string, bool, bool) {
	operands := make([]string, 0, len(values))
	narrowing := false
	for i := 0; i < len(values); i++ {
		value := values[i]
		if !strings.HasPrefix(value, "-") {
			operands = append(operands, value)
			continue
		}
		switch strings.ToLower(value) {
		case "-path", "-literalpath", "-destination":
			if i+1 >= len(values) || strings.HasPrefix(values[i+1], "-") {
				return operands, true, narrowing
			}
			i++
			operands = append(operands, values[i])
		case "-raw", "-wait", "-force", "-recurse", "-r",
			"-rec", "-recurse:$true", "-recurse:$false", "-r:$true", "-r:$false", "-rec:$true", "-rec:$false",
			"-confirm", "-confirm:$true", "-confirm:$false",
			"-whatif", "-whatif:$true", "-whatif:$false",
			"-passthru", "-container":
			continue
		case "-filter", "-include", "-exclude", "-encoding", "-readcount", "-totalcount", "-tail", "-stream", "-credential", "-erroraction", "-warningaction", "-informationaction":
			if i+1 >= len(values) || strings.HasPrefix(values[i+1], "-") {
				return operands, true, narrowing
			}
			if strings.EqualFold(value, "-filter") || strings.EqualFold(value, "-include") || strings.EqualFold(value, "-exclude") {
				narrowing = true
			}
			i++
		default:
			return operands, true, narrowing
		}
	}
	return operands, false, narrowing
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

type windowsLiteralWord struct {
	value         string
	leadingQuoted bool
}

func splitLiteralWindows(command string, powershell bool) ([]string, bool) {
	words, ok := splitLiteralWindowsWords(command, powershell)
	if !ok {
		return nil, false
	}
	values := make([]string, len(words))
	for index, word := range words {
		values[index] = word.value
	}
	return values, true
}

func splitLiteralWindowsWords(command string, powershell bool) ([]windowsLiteralWord, bool) {
	if strings.TrimSpace(command) == "" || strings.ContainsAny(command, "\r\n\x00") {
		return nil, false
	}
	if powershell && !reviewedPowerShellDollarSyntax(command) {
		return nil, false
	}
	if !powershell && strings.ContainsAny(command, "%!^") {
		return nil, false
	}

	var words []windowsLiteralWord
	var current strings.Builder
	var quote rune
	wordStarted := false
	leadingQuoted := false
	flush := func() {
		if wordStarted {
			words = append(words, windowsLiteralWord{value: current.String(), leadingQuoted: leadingQuoted})
			current.Reset()
			wordStarted = false
			leadingQuoted = false
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
			if !wordStarted {
				leadingQuoted = true
			}
			quote = char
			wordStarted = true
			continue
		}
		if strings.ContainsRune("&|<>;,`(){}*?[]", char) {
			return nil, false
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

func splitLiteralWindowsStatements(command string, powershell bool) ([]string, bool) {
	if strings.TrimSpace(command) == "" || strings.ContainsRune(command, '\x00') {
		return nil, false
	}
	var statements []string
	var current strings.Builder
	var quote rune
	flush := func() bool {
		value := strings.TrimSpace(current.String())
		current.Reset()
		if value == "" {
			return false
		}
		statements = append(statements, value)
		return true
	}
	for index, char := range command {
		if quote != 0 {
			current.WriteRune(char)
			if char == quote {
				quote = 0
			}
			continue
		}
		if char == '"' || powershell && char == '\'' {
			quote = char
			current.WriteRune(char)
			continue
		}
		if char == '\r' || char == '\n' || powershell && char == ';' || !powershell && char == '&' {
			if !powershell && char == '&' {
				previousAmpersand := index > 0 && command[index-1] == '&'
				nextAmpersand := index+1 < len(command) && command[index+1] == '&'
				if previousAmpersand || nextAmpersand {
					return nil, false
				}
			}
			if !flush() {
				return nil, false
			}
			continue
		}
		if powershell && char == '&' {
			if strings.TrimSpace(current.String()) == "" {
				current.WriteRune(char)
				continue
			}
			return nil, false
		}
		if char == '|' {
			return nil, false
		}
		current.WriteRune(char)
	}
	if quote != 0 || !flush() {
		return nil, false
	}
	return statements, true
}

func trimPowerShellCallOperator(statement string) string {
	trimmed := strings.TrimSpace(statement)
	if !strings.HasPrefix(trimmed, "&") {
		return trimmed
	}
	return strings.TrimSpace(strings.TrimPrefix(trimmed, "&"))
}

func reviewedPowerShellCommandPayload(argv []string) (string, bool) {
	if len(argv) == 0 {
		return "", false
	}
	switch executableBase(argv[0]) {
	case "powershell", "pwsh":
	default:
		return "", false
	}
	for index := 1; index < len(argv); index++ {
		value := strings.ToLower(argv[index])
		switch value {
		case "-nologo", "-noprofile", "-noninteractive", "-noexit", "-mta", "-sta":
			continue
		case "-executionpolicy", "-ep", "-inputformat", "-outputformat", "-windowstyle", "-workingdirectory":
			index++
			if index >= len(argv) {
				return "", false
			}
			continue
		case "-command", "-c":
			if index+1 >= len(argv) {
				return "", false
			}
			return strings.Join(argv[index+1:], " "), true
		default:
			return "", false
		}
	}
	return "", false
}

func reviewedCMDCommandPayload(argv []string) (string, bool) {
	if len(argv) == 0 || executableBase(argv[0]) != "cmd" {
		return "", false
	}
	for index := 1; index < len(argv); index++ {
		value := strings.ToLower(argv[index])
		switch {
		case value == "/d" || value == "/q" || value == "/a" || value == "/u":
			continue
		case strings.HasPrefix(value, "/e:") || strings.HasPrefix(value, "/f:") || strings.HasPrefix(value, "/v:"):
			continue
		case value == "/c" || value == "/k":
			if index+1 >= len(argv) {
				return "", false
			}
			return strings.Join(argv[index+1:], " "), true
		default:
			return "", false
		}
	}
	return "", false
}

func reviewedCMDWrapperPayload(words []windowsLiteralWord) (string, bool) {
	if len(words) < 2 {
		return "", false
	}
	switch executableBase(words[0].value) {
	case "call":
		if strings.HasPrefix(words[1].value, ":") || strings.EqualFold(words[1].value, "/?") {
			return "", false
		}
		return joinWindowsLiteralWords(words[1:])
	case "start":
		index := 1
		titleConsumed := false
		for index < len(words) {
			word := words[index]
			value := strings.ToLower(word.value)
			if word.leadingQuoted && !titleConsumed {
				titleConsumed = true
				index++
				continue
			}
			switch value {
			case "/wait", "/b", "/i", "/min", "/max", "/separate", "/shared", "/low", "/normal", "/high", "/realtime", "/abovenormal", "/belownormal":
				index++
				continue
			case "/d", "/node", "/affinity", "/machine":
				if index+1 >= len(words) {
					return "", false
				}
				index += 2
				continue
			}
			if strings.HasPrefix(value, "/d:") || strings.HasPrefix(value, "/node:") || strings.HasPrefix(value, "/affinity:") || strings.HasPrefix(value, "/machine:") {
				index++
				continue
			}
			if strings.HasPrefix(value, "/") {
				return "", false
			}
			break
		}
		if index >= len(words) {
			return "", false
		}
		return joinWindowsLiteralWords(words[index:])
	default:
		return "", false
	}
}

func windowsLiteralWordValues(words []windowsLiteralWord) []string {
	values := make([]string, len(words))
	for index, word := range words {
		values[index] = word.value
	}
	return values
}

func joinWindowsLiteralWords(words []windowsLiteralWord) (string, bool) {
	if len(words) == 0 {
		return "", false
	}
	values := make([]string, len(words))
	for index, word := range words {
		if strings.ContainsRune(word.value, '"') {
			return "", false
		}
		value := word.value
		if word.leadingQuoted || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
			value = `"` + value + `"`
		}
		values[index] = value
	}
	return strings.Join(values, " "), true
}

func reviewedPowerShellDollarSyntax(command string) bool {
	quote := byte(0)
	for index := 0; index < len(command); index++ {
		char := command[index]
		if quote != 0 {
			if char == quote {
				quote = 0
				continue
			}
			if char != '$' {
				continue
			}
		} else if char == '\'' || char == '"' {
			quote = char
			continue
		} else if char != '$' {
			continue
		}
		start := index
		for start > 0 && !unicode.IsSpace(rune(command[start-1])) && command[start-1] != '\'' && command[start-1] != '"' {
			start--
		}
		end := index + 1
		for end < len(command) && !unicode.IsSpace(rune(command[end])) && command[end] != '\'' && command[end] != '"' {
			end++
		}
		switch strings.ToLower(command[start:end]) {
		case "-whatif:$true", "-whatif:$false", "-confirm:$true", "-confirm:$false",
			"-recurse:$true", "-recurse:$false", "-r:$true", "-r:$false", "-rec:$true", "-rec:$false":
		default:
			return false
		}
	}
	return true
}

func hasFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

func (e *Evaluator) hasCatastrophicWindowsTarget(values []string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, "-") {
			continue
		}
		if e.boundaries.protectsRecursiveDelete(value) {
			return true
		}
	}
	return false
}

func (e *Evaluator) normalizePowerShellFileOperand(value string) string {
	if len(value) >= len("FileSystem::") && strings.EqualFold(value[:len("FileSystem::")], "FileSystem::") {
		value = value[len("FileSystem::"):]
	}
	normalized := strings.ReplaceAll(value, `\`, "/")
	switch normalized {
	case "~", "~/", "~/.":
		return e.boundaries.home
	default:
		return value
	}
}

func isWindowsAbsolutePath(value string) bool {
	return len(value) >= 3 && value[1] == ':' && value[2] == '/' || strings.HasPrefix(value, "//")
}

func windowsPathWithin(candidate, root string) bool {
	candidate = strings.TrimSuffix(path.Clean(candidate), "/")
	root = strings.TrimSuffix(path.Clean(root), "/")
	return strings.EqualFold(candidate, root) || strings.HasPrefix(strings.ToLower(candidate), strings.ToLower(root)+"/")
}
