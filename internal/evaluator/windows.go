package evaluator

import (
	"path"
	"strconv"
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
		statement, callOperator := trimPowerShellCallOperator(statement)
		argv, leadingQuoted, literal := splitLiteralWindows(statement, true)
		if !literal {
			result.addGap(gap("ambiguous_powershell", "PowerShell input is not a high-confidence literal command."))
			continue
		}
		if leadingQuoted[0] && !callOperator {
			result.addGap(gap("ambiguous_powershell", "A quoted PowerShell command name requires the call operator."))
			continue
		}
		if script, nested := reviewedPowerShellCommandPayload(argv); nested {
			result.merge(e.evaluatePowerShellDepth(script, cwd, depth+1))
		} else if script, nested := reviewedCMDCommandPayload(argv); nested {
			result.merge(e.evaluateCMDDepth(script, cwd, depth+1))
		} else {
			result.merge(e.evaluateWindowsArgv(argv, leadingQuoted, cwd, true))
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
			result.merge(e.evaluateWindowsArgv(argv, nil, cwd, false))
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

func (e *Evaluator) evaluateWindowsArgv(values []string, leadingQuoted []bool, cwd string, powershell bool) scanResult {
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
		if !powershell && cmdFileInformational(values[1:]) {
			return result
		}
		if powershell {
			parsed, ambiguous := powerShellFileOperands(base, values[1:], leadingQuoted[1:])
			if ambiguous {
				result.addGap(gap("ambiguous_powershell_options", "PowerShell file-command options are outside Ward classification."))
				return result
			}
			if parsed.whatIf {
				return result
			}
			if parsed.narrowing {
				result.addGap(gap("ambiguous_powershell_options", "A PowerShell provider selector narrows the file operation."))
				return result
			}
			fileOperands = parsed.targets
			for index := range fileOperands {
				fileOperands[index] = e.normalizePowerShellFileOperand(fileOperands[index])
			}
			for index := range parsed.moveSources {
				parsed.moveSources[index] = e.normalizePowerShellFileOperand(parsed.moveSources[index])
			}
			for _, value := range fileOperands {
				if deleteCommand && e.boundaries.protectsCriticalMetadata(value) {
					return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
				}
			}
			for _, value := range parsed.moveSources {
				if moveCommand && e.boundaries.protectsCriticalRelocation(value) {
					return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
				}
			}
			if deleteCommand && parsed.recursive && e.hasCatastrophicWindowsTarget(fileOperands) {
				return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
			}
		} else {
			fileOperands = cmdFileOperands(values[1:])
			for index, value := range fileOperands {
				if strings.HasPrefix(value, "/") && len(value) <= 3 {
					continue
				}
				moveSource := moveCommand && index < len(fileOperands)-1
				if deleteCommand && e.boundaries.protectsCriticalMetadata(value) || moveSource && e.boundaries.protectsCriticalRelocation(value) {
					return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
				}
			}
		}
	}
	operationArgs, operationGap := unwrapOperationGlobalOptions(base, argv[1:])
	result.addGap(operationGap)

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

func cmdFileInformational(values []string) bool {
	for _, value := range values {
		if strings.EqualFold(value, "/?") {
			return true
		}
	}
	return false
}

type powerShellCommonParameter struct {
	handled       bool
	valid         bool
	canonicalName string
	consumed      int
	whatIf        bool
}

type powerShellFileArguments struct {
	targets     []string
	moveSources []string
	recursive   bool
	narrowing   bool
	whatIf      bool
}

type powerShellFileCommand uint8

const (
	powerShellFileUnknown powerShellFileCommand = iota
	powerShellFileGet
	powerShellFileCopy
	powerShellFileMove
	powerShellFileRemove
	powerShellFileClear
)

func powerShellFileOperands(base string, values []string, leadingQuoted []bool) (powerShellFileArguments, bool) {
	parsed := powerShellFileArguments{}
	command := classifyPowerShellFileCommand(base)
	if command == powerShellFileUnknown {
		return parsed, true
	}
	positional := make([]string, 0, 2)
	var namedSource, namedDestination, sourceParameter string
	seenCommon := make(map[string]struct{})
	seenCommand := make(map[string]struct{})
	for i := 0; i < len(values); i++ {
		value := values[i]
		if !strings.HasPrefix(value, "-") || powerShellLeadingQuoted(leadingQuoted, i) {
			positional = append(positional, value)
			continue
		}
		common := parsePowerShellCommonParameter(values, leadingQuoted, i)
		if common.handled {
			if !common.valid || (common.canonicalName == "whatif" || common.canonicalName == "confirm") && !powerShellSupportsShouldProcess(command) {
				return parsed, true
			}
			if _, duplicate := seenCommon[common.canonicalName]; duplicate {
				return parsed, true
			}
			seenCommon[common.canonicalName] = struct{}{}
			i += common.consumed
			if common.canonicalName == "whatif" {
				parsed.whatIf = common.whatIf
			}
			continue
		}
		name, attached, hasAttached := splitPowerShellParameter(value)
		canonical, kind, allowed := powerShellCommandParameter(command, name)
		if !allowed {
			return parsed, true
		}
		if _, duplicate := seenCommand[canonical]; duplicate {
			return parsed, true
		}
		seenCommand[canonical] = struct{}{}
		switch kind {
		case "switch":
			if hasAttached {
				if _, valid := exactPowerShellBoolean(attached); !valid {
					return parsed, true
				}
			}
		case "recurse":
			boolean := true
			if hasAttached {
				var valid bool
				boolean, valid = exactPowerShellBoolean(attached)
				if !valid {
					return parsed, true
				}
			}
			parsed.recursive = boolean
		case "value", "source", "destination":
			argument, consumed, valid := powerShellStaticParameterValue(values, leadingQuoted, i, attached, hasAttached)
			if !valid {
				return parsed, true
			}
			i += consumed
			switch kind {
			case "source":
				if sourceParameter != "" && sourceParameter != canonical {
					return parsed, true
				}
				sourceParameter = canonical
				namedSource = argument
			case "destination":
				namedDestination = argument
			case "value":
				if canonical == "filter" || canonical == "include" || canonical == "exclude" || canonical == "stream" && command == powerShellFileRemove {
					parsed.narrowing = true
				}
			}
		default:
			return parsed, true
		}
	}

	source, destination, valid := bindPowerShellFileOperands(command, namedSource, namedDestination, positional)
	if !valid {
		return parsed, true
	}
	switch command {
	case powerShellFileMove:
		parsed.moveSources = []string{source}
		parsed.targets = []string{source, destination}
	case powerShellFileCopy:
		parsed.targets = []string{source, destination}
	default:
		parsed.targets = []string{source}
	}
	return parsed, false
}

func classifyPowerShellFileCommand(base string) powerShellFileCommand {
	switch base {
	case "get-content", "gc", "type":
		return powerShellFileGet
	case "copy-item", "cp":
		return powerShellFileCopy
	case "move-item", "mv", "mi", "move":
		return powerShellFileMove
	case "remove-item", "rm", "ri", "del", "erase", "rd", "rmdir":
		return powerShellFileRemove
	case "clear-content":
		return powerShellFileClear
	default:
		return powerShellFileUnknown
	}
}

func powerShellSupportsShouldProcess(command powerShellFileCommand) bool {
	return command == powerShellFileCopy || command == powerShellFileMove || command == powerShellFileRemove || command == powerShellFileClear
}

func powerShellCommandParameter(command powerShellFileCommand, name string) (string, string, bool) {
	switch name {
	case "path":
		return "path", "source", true
	case "literalpath", "pspath", "lp":
		return "literalpath", "source", true
	case "filter", "include", "exclude":
		return name, "value", true
	case "force":
		return "force", "switch", true
	}
	switch command {
	case powerShellFileGet:
		switch name {
		case "raw", "wait", "asbytestream":
			return name, "switch", true
		case "delimiter", "encoding", "readcount", "stream":
			return name, "value", true
		case "totalcount", "first", "head":
			return "totalcount", "value", true
		case "tail", "last":
			return "tail", "value", true
		}
	case powerShellFileCopy:
		switch name {
		case "destination":
			return "destination", "destination", true
		case "container", "passthru":
			return name, "switch", true
		case "recurse", "r", "rec":
			return "recurse", "recurse", true
		}
	case powerShellFileMove:
		switch name {
		case "destination":
			return "destination", "destination", true
		case "passthru":
			return "passthru", "switch", true
		}
	case powerShellFileRemove:
		switch name {
		case "recurse", "r", "rec":
			return "recurse", "recurse", true
		case "stream":
			return "stream", "value", true
		}
	case powerShellFileClear:
		if name == "stream" {
			return "stream", "value", true
		}
	}
	return "", "", false
}

func powerShellStaticParameterValue(values []string, leadingQuoted []bool, index int, attached string, hasAttached bool) (string, int, bool) {
	if hasAttached {
		return attached, 0, attached != ""
	}
	if index+1 >= len(values) || strings.HasPrefix(values[index+1], "-") && !powerShellLeadingQuoted(leadingQuoted, index+1) {
		return "", 0, false
	}
	return values[index+1], 1, true
}

func powerShellLeadingQuoted(leadingQuoted []bool, index int) bool {
	return index >= 0 && index < len(leadingQuoted) && leadingQuoted[index]
}

func bindPowerShellFileOperands(command powerShellFileCommand, namedSource, namedDestination string, positional []string) (string, string, bool) {
	switch command {
	case powerShellFileCopy, powerShellFileMove:
		switch {
		case namedSource != "" && namedDestination != "" && len(positional) == 0:
			return namedSource, namedDestination, true
		case namedSource != "" && namedDestination == "" && len(positional) == 1:
			return namedSource, positional[0], true
		case namedSource == "" && namedDestination != "" && len(positional) == 1:
			return positional[0], namedDestination, true
		case namedSource == "" && namedDestination == "" && len(positional) == 2:
			return positional[0], positional[1], true
		default:
			return "", "", false
		}
	default:
		if namedDestination != "" {
			return "", "", false
		}
		if namedSource != "" && len(positional) == 0 {
			return namedSource, "", true
		}
		if namedSource == "" && len(positional) == 1 {
			return positional[0], "", true
		}
		return "", "", false
	}
}

func parsePowerShellCommonParameter(values []string, leadingQuoted []bool, index int) powerShellCommonParameter {
	name, attached, hasAttached := splitPowerShellParameter(values[index])
	canonical, kind, recognized := powerShellCommonParameterKind(name)
	if !recognized {
		return powerShellCommonParameter{}
	}
	parsed := powerShellCommonParameter{handled: true, canonicalName: canonical}
	switch kind {
	case "switch":
		if !hasAttached {
			parsed.valid = true
			parsed.whatIf = canonical == "whatif"
			return parsed
		}
		boolean, valid := exactPowerShellBoolean(attached)
		parsed.valid = valid
		parsed.whatIf = canonical == "whatif" && boolean
		return parsed
	case "action", "variable", "buffer":
		argument := attached
		if !hasAttached {
			if index+1 >= len(values) || strings.HasPrefix(values[index+1], "-") && !powerShellLeadingQuoted(leadingQuoted, index+1) {
				return parsed
			}
			argument = values[index+1]
			parsed.consumed = 1
		}
		switch kind {
		case "action":
			parsed.valid = validPowerShellActionPreference(argument)
		case "variable":
			parsed.valid = validPowerShellVariableName(argument)
		case "buffer":
			parsed.valid = validPowerShellOutBuffer(argument)
		}
		return parsed
	default:
		return parsed
	}
}

func splitPowerShellParameter(value string) (string, string, bool) {
	if !strings.HasPrefix(value, "-") || len(value) == 1 {
		return "", "", false
	}
	name, argument, attached := strings.Cut(value[1:], ":")
	return strings.ToLower(name), argument, attached
}

func powerShellCommonParameterKind(name string) (string, string, bool) {
	switch strings.ToLower(name) {
	case "debug", "db":
		return "debug", "switch", true
	case "verbose", "vb":
		return "verbose", "switch", true
	case "whatif", "wi":
		return "whatif", "switch", true
	case "confirm", "cf":
		return "confirm", "switch", true
	case "erroraction", "ea":
		return "erroraction", "action", true
	case "informationaction", "infa":
		return "informationaction", "action", true
	case "warningaction", "wa":
		return "warningaction", "action", true
	case "errorvariable", "ev":
		return "errorvariable", "variable", true
	case "informationvariable", "iv":
		return "informationvariable", "variable", true
	case "outvariable", "ov":
		return "outvariable", "variable", true
	case "pipelinevariable", "pv":
		return "pipelinevariable", "variable", true
	case "warningvariable", "wv":
		return "warningvariable", "variable", true
	case "outbuffer", "ob":
		return "outbuffer", "buffer", true
	default:
		return "", "", false
	}
}

func exactPowerShellBoolean(value string) (bool, bool) {
	switch strings.ToLower(value) {
	case "$true":
		return true, true
	case "$false":
		return false, true
	default:
		return false, false
	}
}

func validPowerShellActionPreference(value string) bool {
	switch strings.ToLower(value) {
	case "silentlycontinue", "stop", "continue", "inquire", "ignore", "break", "0", "1", "2", "3", "4", "6":
		return true
	default:
		return false
	}
}

func validPowerShellVariableName(value string) bool {
	value = strings.TrimPrefix(value, "+")
	if value == "" || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return false
	}
	if separator := strings.IndexByte(value, ':'); separator >= 0 {
		scope := strings.ToLower(value[:separator])
		if scope != "global" && scope != "local" && scope != "script" && scope != "private" {
			return false
		}
		value = value[separator+1:]
		if value == "" || strings.ContainsRune(value, ':') {
			return false
		}
	}
	return !strings.ContainsAny(value, `/\\`)
}

func validPowerShellOutBuffer(value string) bool {
	unsigned := strings.TrimPrefix(value, "+")
	base := 10
	if strings.HasPrefix(strings.ToLower(unsigned), "0x") {
		base = 16
		unsigned = unsigned[2:]
	}
	if unsigned == "" {
		return false
	}
	parsed, err := strconv.ParseInt(unsigned, base, 32)
	return err == nil && parsed >= 0
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

func splitLiteralWindows(command string, powershell bool) ([]string, []bool, bool) {
	words, ok := splitLiteralWindowsWords(command, powershell)
	if !ok {
		return nil, nil, false
	}
	values := make([]string, len(words))
	leadingQuoted := make([]bool, len(words))
	for index, word := range words {
		values[index] = word.value
		leadingQuoted[index] = word.leadingQuoted
	}
	return values, leadingQuoted, true
}

func splitLiteralWindowsWords(command string, powershell bool) ([]windowsLiteralWord, bool) {
	if strings.TrimSpace(command) == "" || strings.ContainsAny(command, "\r\n\x00") {
		return nil, false
	}
	if powershell && strings.ContainsRune(command, '`') {
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
	wordHadQuote := false
	flush := func() {
		if wordStarted {
			words = append(words, windowsLiteralWord{value: current.String(), leadingQuoted: leadingQuoted})
			current.Reset()
			wordStarted = false
			leadingQuoted = false
			wordHadQuote = false
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
			if powershell && wordStarted {
				if wordHadQuote || current.Len() == 0 || current.String()[current.Len()-1] != ':' || !strings.HasPrefix(current.String(), "-") {
					return nil, false
				}
			} else if !wordStarted {
				leadingQuoted = true
			}
			quote = char
			wordStarted = true
			wordHadQuote = true
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
	commentBoundary := true
	inLineComment := false
	skipLineFeed := false
	trailingLineComment := false
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
		if skipLineFeed {
			skipLineFeed = false
			if char == '\n' {
				continue
			}
		}
		if inLineComment {
			if char == '\r' || char == '\n' {
				inLineComment = false
				commentBoundary = true
				if char == '\r' {
					skipLineFeed = true
				}
			}
			continue
		}
		if powershell && char == '`' {
			return nil, false
		}
		if quote != 0 {
			current.WriteRune(char)
			if char == quote {
				quote = 0
				commentBoundary = true
			}
			continue
		}
		if char == '"' || powershell && char == '\'' {
			quote = char
			current.WriteRune(char)
			commentBoundary = false
			continue
		}
		if powershell && char == '#' && commentBoundary {
			flush()
			inLineComment = true
			trailingLineComment = true
			continue
		}
		if char == '\r' || char == '\n' || powershell && char == ';' || !powershell && char == '&' {
			if powershell && (char == '\r' || char == '\n') && trailingLineComment && strings.TrimSpace(current.String()) == "" {
				continue
			}
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
			commentBoundary = true
			trailingLineComment = false
			continue
		}
		if powershell && char == '&' {
			if strings.TrimSpace(current.String()) == "" {
				current.WriteRune(char)
				commentBoundary = false
				trailingLineComment = false
				continue
			}
			return nil, false
		}
		if char == '|' {
			return nil, false
		}
		current.WriteRune(char)
		if unicode.IsSpace(char) {
			commentBoundary = true
			continue
		}
		commentBoundary = powershell && strings.ContainsRune(")}]", char)
		trailingLineComment = false
	}
	if quote != 0 {
		return nil, false
	}
	if strings.TrimSpace(current.String()) != "" {
		flush()
	} else if !trailingLineComment {
		return nil, false
	}
	if len(statements) == 0 {
		return nil, false
	}
	return statements, true
}

func trimPowerShellCallOperator(statement string) (string, bool) {
	trimmed := strings.TrimSpace(statement)
	if !strings.HasPrefix(trimmed, "&") {
		return trimmed, false
	}
	return strings.TrimSpace(strings.TrimPrefix(trimmed, "&")), true
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
	quoteStart := -1
	for index := 0; index < len(command); index++ {
		char := command[index]
		if quote != 0 {
			if char == quote {
				quote = 0
				quoteStart = -1
				continue
			}
			if quote == '\'' {
				if char == '$' && quotedPowerShellSwitchValue(command, quoteStart) {
					return false
				}
				continue
			}
			if char != '$' {
				continue
			}
		} else if char == '\'' || char == '"' {
			quote = char
			quoteStart = index
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
			"-wi:$true", "-wi:$false", "-cf:$true", "-cf:$false",
			"-verbose:$true", "-verbose:$false", "-vb:$true", "-vb:$false",
			"-debug:$true", "-debug:$false", "-db:$true", "-db:$false",
			"-recurse:$true", "-recurse:$false", "-r:$true", "-r:$false", "-rec:$true", "-rec:$false",
			"-force:$true", "-force:$false", "-passthru:$true", "-passthru:$false",
			"-container:$true", "-container:$false", "-raw:$true", "-raw:$false",
			"-wait:$true", "-wait:$false", "-asbytestream:$true", "-asbytestream:$false":
		default:
			return false
		}
	}
	return true
}

func quotedPowerShellSwitchValue(command string, quoteStart int) bool {
	if quoteStart <= 0 || command[quoteStart-1] != ':' {
		return false
	}
	start := quoteStart - 1
	for start > 0 && !unicode.IsSpace(rune(command[start-1])) {
		start--
	}
	switch strings.ToLower(command[start:quoteStart]) {
	case "-whatif:", "-wi:", "-confirm:", "-cf:",
		"-verbose:", "-vb:", "-debug:", "-db:",
		"-recurse:", "-r:", "-rec:", "-force:", "-passthru:",
		"-container:", "-raw:", "-wait:", "-asbytestream:":
		return true
	default:
		return false
	}
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
