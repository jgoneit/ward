package evaluator

import (
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/jgoneit/ward/internal/contract"
	"mvdan.cc/sh/v3/syntax"
)

const maxNestedShellDepth = 3

var (
	dropDatabaseSQL      = regexp.MustCompile(`(?i)^drop[[:space:]]+database[[:space:]]+(?:if[[:space:]]+exists[[:space:]]+)?(?:"[^"]+"|[a-z0-9_.-]+)(?:[[:space:]]+(?:with[[:space:]]*)?\([^;]*\))?[[:space:]]*;?$`)
	dropDatabaseMySQLSQL = regexp.MustCompile(`(?i)^drop[[:space:]]+(?:database|schema)[[:space:]]+(?:if[[:space:]]+exists[[:space:]]+)?(?:` + "`[^`]+`" + `|[a-z0-9_.-]+)[[:space:]]*;?$`)
	dropSchemaCascadeSQL = regexp.MustCompile(`(?i)^drop[[:space:]]+schema[[:space:]]+(?:if[[:space:]]+exists[[:space:]]+)?(?:"[^"]+"|[a-z0-9_.-]+)[[:space:]]+cascade[[:space:]]*;?$`)
)

type literalArg struct {
	value  string
	static bool
}

func (e *Evaluator) evaluatePOSIX(command, cwd string, depth int) scanResult {
	if depth > maxNestedShellDepth {
		return scanResult{gap: gap("nested_shell_limit", "Nested shell evaluation exceeded its bounded depth.")}
	}
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return scanResult{gap: gap("shell_parse_error", "The POSIX shell parser rejected the command.")}
	}
	if exactInteractive(file) {
		return denied("WARD_INTERACTIVE_SESSION", "An explicit interactive session is denied.")
	}
	if compoundInteractiveTail(file) {
		return denied("WARD_INTERACTIVE_SESSION", "An explicit interactive session is denied.")
	}
	pwdCall := singleSimpleCall(file)

	result := scanResult{}
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil || result.deny != nil {
			return false
		}
		switch typed := node.(type) {
		case *syntax.FuncDecl:
			// A function declaration does not execute its body. A later invocation
			// appears as its own CallExpr and is evaluated independently.
			result.addGap(gap("shell_function", "A shell function body is not evaluated until invocation."))
			return false
		case *syntax.CallExpr:
			callResult := e.evaluatePOSIXCall(typed, cwd, depth, typed == pwdCall)
			result.merge(callResult)
		case *syntax.Redirect:
			switch typed.Op {
			case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
				result.addGap(gap("inline_shell_input", "Here-document and here-string input is outside Ward command classification."))
				return true
			case syntax.DplIn, syntax.DplOut:
				return true
			}
			value, static := literalWord(typed.Word)
			if !static {
				result.addGap(gap("dynamic_shell_word", "A shell redirection contains runtime expansion."))
				break
			}
			if ruleID, protected := e.matchProtectedPath(value, cwd, false); protected {
				result.merge(denied(ruleID, secretReason))
			}
		}
		return result.deny == nil
	})
	return result
}

func compoundInteractiveTail(file *syntax.File) bool {
	if file == nil || len(file.Stmts) == 0 {
		return false
	}
	for _, statement := range file.Stmts {
		if interactiveChannelStatement(statement) {
			return true
		}
		if statementStopsFollowingCommands(statement) {
			return false
		}
	}
	return false
}

func interactiveChannelStatement(statement *syntax.Stmt) bool {
	if statement == nil || len(statement.Redirs) != 0 || statement.Negated ||
		statement.Background || statement.Coprocess || statement.Disown {
		return false
	}
	switch command := statement.Cmd.(type) {
	case *syntax.CallExpr:
		if len(command.Args) == 0 {
			return false
		}
		argv := make([]literalArg, len(command.Args))
		for index, word := range command.Args {
			value, static := literalWord(word)
			if !static {
				return false
			}
			argv[index] = literalArg{value: value, static: true}
		}
		unwrapped, unwrapGap, envDump := unwrapPOSIX(argv, false)
		return unwrapGap == nil && !envDump && inputDrivenInteractive(unwrapped)
	case *syntax.BinaryCmd:
		// In a pipeline, only the left-most command retains the tool's stdin.
		// The right side receives the upstream pipe and is not an unobserved host
		// input channel.
		if command.Op == syntax.Pipe || command.Op == syntax.PipeAll {
			return interactiveChannelStatement(command.X)
		}
		if interactiveChannelStatement(command.X) {
			return true
		}
		if status, known := literalStatementStatus(command.X); known {
			if command.Op == syntax.AndStmt && !status || command.Op == syntax.OrStmt && status {
				return false
			}
		}
		return interactiveChannelStatement(command.Y)
	case *syntax.Subshell:
		return interactiveChannelStatements(command.Stmts)
	case *syntax.Block:
		return interactiveChannelStatements(command.Stmts)
	default:
		return false
	}
}

func interactiveChannelStatements(statements []*syntax.Stmt) bool {
	for _, statement := range statements {
		if interactiveChannelStatement(statement) {
			return true
		}
		if statementStopsFollowingCommands(statement) {
			return false
		}
	}
	return false
}

func literalStatementStatus(statement *syntax.Stmt) (bool, bool) {
	if statement == nil || len(statement.Redirs) != 0 || statement.Background || statement.Coprocess || statement.Disown {
		return false, false
	}
	call, ok := statement.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false, false
	}
	value, static := literalWord(call.Args[0])
	if !static {
		return false, false
	}
	var status bool
	switch posixExecutableBase(value) {
	case "true", ":":
		status = true
	case "false":
		status = false
	default:
		return false, false
	}
	if statement.Negated {
		status = !status
	}
	return status, true
}

func statementStopsFollowingCommands(statement *syntax.Stmt) bool {
	if statement == nil || len(statement.Redirs) != 0 || statement.Background || statement.Coprocess || statement.Disown {
		return false
	}
	call, ok := statement.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	value, static := literalWord(call.Args[0])
	return static && (posixExecutableBase(value) == "exit" || posixExecutableBase(value) == "return")
}

func singleSimpleCall(file *syntax.File) *syntax.CallExpr {
	if file == nil || len(file.Stmts) != 1 {
		return nil
	}
	statement := file.Stmts[0]
	if statement == nil || statement.Semicolon.IsValid() || statement.Background || statement.Coprocess || statement.Disown {
		return nil
	}
	call, _ := statement.Cmd.(*syntax.CallExpr)
	return call
}

func exactInteractive(file *syntax.File) bool {
	if file == nil || len(file.Stmts) != 1 {
		return false
	}
	stmt := file.Stmts[0]
	if stmt == nil || len(stmt.Redirs) != 0 || stmt.Semicolon.IsValid() ||
		stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) < 1 {
		return false
	}
	argv := make([]literalArg, len(call.Args))
	for i, arg := range call.Args {
		value, static := literalWord(arg)
		if !static {
			return false
		}
		argv[i] = literalArg{value: value, static: true}
	}
	unwrapped, unwrapGap, envDump := unwrapPOSIX(argv, false)
	return unwrapGap == nil && !envDump && inputDrivenInteractive(unwrapped)
}

func exactInteractiveArgv(values []string) bool {
	if len(values) == 1 {
		return isInteractiveExecutable(posixExecutableBase(values[0]))
	}
	return len(values) == 2 && values[1] == "-i" &&
		isExplicitInteractiveFlagExecutable(posixExecutableBase(values[0]))
}

func isExplicitInteractiveFlagExecutable(base string) bool {
	if isPythonExecutable(base) {
		return true
	}
	switch base {
	case "bash", "sh", "zsh", "node":
		return true
	default:
		return false
	}
}

func isInteractiveExecutable(base string) bool {
	if isPythonExecutable(base) {
		return true
	}
	switch base {
	case "bash", "sh", "zsh", "node", "ruby", "perl",
		"psql", "mysql", "mariadb", "sqlite3", "sqlplus", "mongosh",
		"powershell", "pwsh", "cmd":
		return true
	default:
		return false
	}
}

// inputDrivenInteractive recognizes only literal invocations that start a
// shell/REPL or read executable input from the still-open tool stdin. It runs
// after benign wrappers such as env and command are removed, preventing one
// approved tool call from becoming an unobserved command channel.
func inputDrivenInteractive(argv []literalArg) bool {
	if len(argv) == 0 {
		return false
	}
	values := make([]string, len(argv))
	for index, arg := range argv {
		if !arg.static {
			return false
		}
		values[index] = arg.value
	}
	if exactInteractiveArgv(values) {
		return true
	}
	base := posixExecutableBase(values[0])
	args := values[1:]
	if isPythonExecutable(base) {
		return pythonReadsToolInput(args)
	}
	switch base {
	case "bash", "sh", "zsh":
		parsed := parseShellInvocation(base, argv[1:])
		return parsed.known && parsed.readsStdin
	case "node":
		return nodeReadsToolInput(args)
	case "psql":
		return psqlOptionOnlyInvocation(args)
	case "mysql", "mariadb":
		return mysqlOptionOnlyInvocation(args)
	default:
		return false
	}
}

type shellInvocation struct {
	command       string
	hasCommand    bool
	commandStatic bool
	readsStdin    bool
	known         bool
}

func parseShellInvocation(base string, args []literalArg) shellInvocation {
	stdinForced := false
	noExec := false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !arg.static {
			return shellInvocation{}
		}
		value := arg.value
		if value == "--help" || value == "--version" {
			return shellInvocation{known: true}
		}
		if value == "--" {
			return shellInvocation{readsStdin: !noExec && (stdinForced || index+1 == len(args)), known: true}
		}
		if value == "-" {
			return shellInvocation{readsStdin: !noExec, known: true}
		}
		if !strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "+") {
			return shellInvocation{readsStdin: !noExec && stdinForced, known: true}
		}
		if command, stdin, disablesExec, ok := reviewedShellShortCluster(base, value); ok {
			stdinForced = stdinForced || stdin
			noExec = noExec || disablesExec
			if command {
				if noExec {
					return shellInvocation{known: true}
				}
				if index+1 >= len(args) {
					return shellInvocation{known: true}
				}
				return shellInvocation{
					command:       args[index+1].value,
					hasCommand:    true,
					commandStatic: args[index+1].static,
					known:         true,
				}
			}
			continue
		}
		if reviewedShellLongFlag(base, value) {
			noExec = noExec || shellNoExecLongFlag(value)
			continue
		}
		if reviewedShellValueOption(base, value) {
			if index+1 >= len(args) || !args[index+1].static {
				return shellInvocation{}
			}
			index++
			continue
		}
		return shellInvocation{}
	}
	return shellInvocation{readsStdin: !noExec, known: true}
}

func reviewedShellShortCluster(base, value string) (command, stdin, noExec, ok bool) {
	if len(value) < 2 || value[0] != '-' || strings.HasPrefix(value, "--") {
		return false, false, false, false
	}
	allowed := ""
	switch base {
	case "bash":
		allowed = "abefhklmnptuvxBCHPirsDc"
	case "sh":
		allowed = "aefnuvxilsc"
	case "zsh":
		allowed = "dfilnsvxXc"
	default:
		return false, false, false, false
	}
	for _, flag := range value[1:] {
		if !strings.ContainsRune(allowed, flag) {
			return false, false, false, false
		}
		command = command || flag == 'c'
		stdin = stdin || flag == 's'
		noExec = noExec || flag == 'n' || flag == 'D'
	}
	return command, stdin, noExec, true
}

func shellNoExecLongFlag(value string) bool {
	return value == "--dump-po-strings" || value == "--dump-strings" || value == "--pretty-print"
}

func reviewedShellLongFlag(base, value string) bool {
	switch base {
	case "bash":
		return stringIn(value, []string{
			"--debug", "--debugger", "--dump-po-strings", "--dump-strings", "--login",
			"--noediting", "--noprofile", "--norc", "--posix", "--pretty-print",
			"--restricted", "--verbose",
		})
	case "zsh":
		return value == "--no-rcs"
	default:
		return false
	}
}

func reviewedShellValueOption(base, value string) bool {
	if value == "-o" || value == "+o" {
		return true
	}
	if base == "bash" {
		return value == "-O" || value == "+O" || value == "--init-file" || value == "--rcfile"
	}
	return false
}

func pythonReadsToolInput(args []string) bool {
	interactive := false
	for index := 0; index < len(args); index++ {
		value := args[index]
		if stringIn(value, []string{"-h", "--help", "-V", "--version", "-VV"}) {
			return false
		}
		if value == "-i" {
			interactive = true
			continue
		}
		if len(value) > 2 && value[0] == '-' && value[1] != '-' {
			cluster := value[1:]
			valid := true
			for _, flag := range cluster {
				if !strings.ContainsRune("iquBbEIOPsSvx", flag) {
					valid = false
					break
				}
				interactive = interactive || flag == 'i'
			}
			if valid {
				continue
			}
		}
		if stringIn(value, []string{"-q", "-u", "-B", "-b", "-bb", "-E", "-I", "-O", "-OO", "-P", "-s", "-S", "-v", "-x"}) {
			continue
		}
		if value == "-W" || value == "-X" {
			if index+1 >= len(args) {
				return false
			}
			index++
			continue
		}
		if strings.HasPrefix(value, "-W") && len(value) > 2 || strings.HasPrefix(value, "-X") && len(value) > 2 {
			continue
		}
		if value == "--check-hash-based-pycs" {
			if index+1 >= len(args) || !stringIn(args[index+1], []string{"default", "always", "never"}) {
				return false
			}
			index++
			continue
		}
		if strings.HasPrefix(value, "--check-hash-based-pycs=") {
			if !stringIn(strings.TrimPrefix(value, "--check-hash-based-pycs="), []string{"default", "always", "never"}) {
				return false
			}
			continue
		}
		if value == "-c" || value == "-m" {
			return interactive && index+1 < len(args)
		}
		if value == "-" {
			return true
		}
		if value == "--" {
			return interactive || index+1 == len(args)
		}
		if strings.HasPrefix(value, "-") {
			return false
		}
		return interactive
	}
	return true
}

func nodeReadsToolInput(args []string) bool {
	interactive := false
	for index := 0; index < len(args); index++ {
		value := args[index]
		if stringIn(value, []string{"-h", "--help", "-v", "--version"}) {
			return false
		}
		if value == "-i" || value == "--interactive" {
			interactive = true
			continue
		}
		if stringIn(value, []string{"--experimental-repl-await", "--no-warnings", "--trace-warnings"}) {
			continue
		}
		if nodeValueOption(value) {
			if index+1 >= len(args) || args[index+1] == "" {
				return false
			}
			if value == "--input-type" && !validNodeInputType(args[index+1]) {
				return false
			}
			index++
			continue
		}
		if nodeAssignedValueOption(value) {
			continue
		}
		if value == "-e" || value == "--eval" || value == "-p" || value == "--print" {
			return interactive && index+1 < len(args)
		}
		if strings.HasPrefix(value, "--eval=") || strings.HasPrefix(value, "--print=") ||
			strings.HasPrefix(value, "-e") && len(value) > 2 || strings.HasPrefix(value, "-p") && len(value) > 2 {
			return interactive
		}
		if value == "-" {
			return true
		}
		if value == "--" {
			return interactive || index+1 == len(args)
		}
		if strings.HasPrefix(value, "-") {
			return false
		}
		return interactive
	}
	return true
}

func nodeValueOption(value string) bool {
	return stringIn(value, []string{"--input-type", "--require", "-r"})
}

func nodeAssignedValueOption(value string) bool {
	if strings.HasPrefix(value, "--input-type=") {
		return validNodeInputType(strings.TrimPrefix(value, "--input-type="))
	}
	if strings.HasPrefix(value, "--require=") && len(value) > len("--require=") {
		return true
	}
	return strings.HasPrefix(value, "-r") && len(value) > 2
}

func validNodeInputType(value string) bool {
	return stringIn(value, []string{"commonjs", "module", "commonjs-typescript", "module-typescript"})
}

func psqlOptionOnlyInvocation(args []string) bool {
	return reviewedOptionOnlyInvocation(args,
		[]string{"-a", "--echo-all", "-e", "--echo-queries", "-E", "--echo-hidden", "-n", "--no-readline", "-q", "--quiet", "-s", "--single-step", "-S", "--single-line", "-w", "--no-password", "-W", "--password", "-X", "--no-psqlrc"},
		[]string{"-d", "--dbname", "-h", "--host", "-p", "--port", "-U", "--username", "-v", "--set", "-P", "--pset"})
}

func mysqlOptionOnlyInvocation(args []string) bool {
	filtered := make([]string, 0, len(args))
	for _, value := range args {
		if strings.HasPrefix(value, "--password=") || strings.HasPrefix(value, "-p") && len(value) > 2 {
			continue
		}
		filtered = append(filtered, value)
	}
	return reviewedOptionOnlyInvocation(filtered,
		[]string{"-A", "--no-auto-rehash", "--auto-rehash", "--compress", "--ssl", "-q", "--quick", "-s", "--silent", "-N", "--skip-column-names", "-p", "--password"},
		[]string{"-D", "--database", "-h", "--host", "-P", "--port", "-S", "--socket", "-u", "--user", "--protocol", "--default-character-set"})
}

func reviewedOptionOnlyInvocation(args, flags, valueOptions []string) bool {
	if len(args) == 0 {
		return true
	}
	for index := 0; index < len(args); index++ {
		value := args[index]
		if stringIn(value, flags) {
			continue
		}
		matched := false
		for _, option := range valueOptions {
			if value == option {
				if index+1 >= len(args) || args[index+1] == "" || strings.HasPrefix(args[index+1], "-") {
					return false
				}
				index++
				matched = true
				break
			}
			if strings.HasPrefix(value, option+"=") && len(value) > len(option)+1 ||
				len(option) == 2 && strings.HasPrefix(value, option) && len(value) > 2 {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func stringIn(value string, candidates []string) bool {
	for _, candidate := range candidates {
		if value == candidate {
			return true
		}
	}
	return false
}

func (e *Evaluator) evaluatePOSIXCall(call *syntax.CallExpr, cwd string, depth int, resolvePWD bool) scanResult {
	if len(call.Args) == 0 {
		return scanResult{}
	}
	argv := make([]literalArg, len(call.Args))
	result := scanResult{}
	for i, word := range call.Args {
		argv[i].value, argv[i].static = literalWord(word)
		if resolvePWD && !argv[i].static {
			if resolved, exact := exactPWDWord(word, cwd); exact {
				argv[i].value, argv[i].static = resolved, true
			}
		}
		if !argv[i].static {
			result.addGap(gap("dynamic_shell_word", "A shell word contains runtime expansion or globbing."))
		}
	}
	if !argv[0].static {
		return result
	}

	unwrapped, unwrapGap, envDump := unwrapPOSIX(argv, true)
	result.addGap(unwrapGap)
	if envDump {
		return result
	}
	if len(unwrapped) == 0 || !unwrapped[0].static {
		return result
	}
	base := posixExecutableBase(unwrapped[0].value)
	if hasNohupWrapper(argv) && inputDrivenInteractive(unwrapped) {
		result.addGap(gap("nohup_stdin_semantics", "Nohup stdin behavior is outside interactive-session classification."))
	}
	if knownInformationalInterpreterInvocation(base, unwrapped[1:]) {
		return result
	}
	if nested, script, known := nestedShellScript(base, unwrapped[1:]); nested {
		if !known {
			result.addGap(gap("dynamic_interpreter_payload", "A nested shell payload is not a static literal."))
			return result
		}
		result.merge(e.evaluatePOSIX(script, cwd, depth+1))
		return result
	}
	if isInterpreterPayload(base, unwrapped[1:]) {
		result.addGap(gap("interpreter_payload", "Embedded interpreter code is outside Ward command classification."))
	}
	if isOpaqueCommandDispatcher(base) {
		result.addGap(gap("opaque_command_dispatch", "A command dispatcher payload is outside Ward command classification."))
	}

	if ruleID, matched, ambiguous := e.matchAdditiveCommand(unwrapped, false); matched {
		return denied(ruleID, additiveReason)
	} else if ambiguous {
		result.addGap(gap("dynamic_additive_prefix", "An additive command prefix contains runtime expansion."))
	}
	operationArgs, operationGap := unwrapOperationGlobalOptions(base, unwrapped[1:])
	result.addGap(operationGap)

	if base == "rsync" {
		result.merge(e.evaluateRsyncFileOptions(unwrapped[1:], cwd))
		if result.deny != nil {
			return result
		}
	} else if isPatternFileCommand(base) {
		result.merge(e.evaluatePatternFileCommand(base, unwrapped[1:], cwd))
		if result.deny != nil {
			return result
		}
	} else if isFileAccessCommand(base) || base == "source" || base == "." {
		if base == "mv" {
			result.merge(e.evaluateMoveAncestors(unwrapped[1:], cwd))
			if result.deny != nil {
				return result
			}
		}
		for _, arg := range unwrapped[1:] {
			if !arg.static || strings.HasPrefix(arg.value, "-") {
				continue
			}
			candidate := arg.value
			if base == "dd" {
				name, value, found := strings.Cut(candidate, "=")
				if found && (name == "if" || name == "of") {
					candidate = value
				}
			}
			if ruleID, protected := e.matchProtectedPath(candidate, cwd, false); protected {
				return denied(ruleID, secretReason)
			}
		}
	}
	if ruleID, protected := e.secretTransferPath(base, unwrapped[1:], cwd); protected {
		return denied(ruleID, secretReason)
	}

	switch base {
	case "rm":
		if hasRMInformationalOption(unwrapped[1:]) {
			return result
		}
		result.merge(e.evaluateDeleteTargets(unwrapped[1:], cwd))
		if result.deny != nil {
			return result
		}
		if recursiveRMHasUnresolvedHome(unwrapped[1:]) {
			result.addGap(gap("unresolved_home_target", "A recursive deletion target uses unresolved home expansion."))
		}
		if catastrophicRM(unwrapped[1:], cwd) {
			return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
		}
	case "unlink", "rmdir":
		result.merge(e.evaluateDeleteTargets(unwrapped[1:], cwd))
		if result.deny != nil {
			return result
		}
	case "find":
		result.merge(e.evaluateFindPaths(unwrapped[1:], cwd))
		if result.deny != nil {
			return result
		}
		if hasFindCommandAction(unwrapped[1:]) {
			result.addGap(gap("find_command_action", "A find command action is outside Ward command classification."))
		}
		if catastrophicFind(unwrapped[1:], cwd) {
			return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
		}
	case "git":
		if literalAt(operationArgs, 0, "rm") {
			result.merge(e.evaluateDeleteTargets(operationArgs[1:], cwd))
			if result.deny != nil {
				return result
			}
		}
		if literalAt(operationArgs, 0, "mv") {
			result.merge(e.evaluateMoveAncestors(operationArgs[1:], cwd))
			if result.deny != nil {
				return result
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
	if containsDestructiveSQL(base, unwrapped[1:]) {
		return denied("WARD_DESTRUCTIVE_DATABASE", destructiveDBReason)
	}
	return result
}

func hasRMInformationalOption(args []literalArg) bool {
	for _, arg := range args {
		if !arg.static {
			return false
		}
		if arg.value == "--" {
			return false
		}
		if arg.value == "--help" || arg.value == "--version" {
			return true
		}
	}
	return false
}

func hasNohupWrapper(argv []literalArg) bool {
	for _, arg := range argv {
		if arg.static && posixExecutableBase(arg.value) == "nohup" {
			return true
		}
	}
	return false
}

func knownInformationalInterpreterInvocation(base string, args []literalArg) bool {
	if len(args) != 1 || !args[0].static {
		return false
	}
	switch base {
	case "bash", "sh", "zsh":
		return args[0].value == "--help" || args[0].value == "--version"
	default:
		return false
	}
}

func unwrapOperationGlobalOptions(base string, args []literalArg) ([]literalArg, *contract.CoverageGap) {
	current := args
	for len(current) > 0 {
		if !current[0].static {
			return nil, gap("dynamic_global_option", "A global command option contains runtime expansion.")
		}
		value := current[0].value
		if !strings.HasPrefix(value, "-") || value == "-" {
			return current, nil
		}
		switch base {
		case "git":
			switch {
			case value == "--paginate" || value == "-p" || value == "--no-pager" || value == "-P" ||
				value == "--no-replace-objects" || value == "--bare" || value == "--no-optional-locks" ||
				value == "--literal-pathspecs" || value == "--glob-pathspecs" || value == "--noglob-pathspecs" ||
				value == "--icase-pathspecs":
				current = current[1:]
				continue
			case value == "-c":
				if len(current) < 2 || !current[1].static || !validGitConfigOverride(current[1].value) {
					return nil, gap("unsupported_git_global_option", "A Git config override is not a high-confidence literal.")
				}
				current = current[2:]
				continue
			case value == "-C" || value == "--git-dir" || value == "--work-tree" ||
				value == "--namespace" || value == "--super-prefix":
				if len(current) < 2 || !current[1].static {
					return nil, gap("unsupported_git_global_option", "A Git global option is missing a literal argument.")
				}
				current = current[2:]
				continue
			case strings.HasPrefix(value, "-c") && len(value) > 2:
				if !validGitConfigOverride(strings.TrimPrefix(value, "-c")) {
					return nil, gap("unsupported_git_global_option", "A Git config override is not a high-confidence literal.")
				}
				current = current[1:]
				continue
			case literalOptionAssignment(value, "--git-dir"), literalOptionAssignment(value, "--work-tree"),
				literalOptionAssignment(value, "--namespace"), literalOptionAssignment(value, "--super-prefix"),
				literalOptionAssignment(value, "--exec-path"):
				current = current[1:]
				continue
			}
		case "terraform":
			if value == "-no-color" {
				current = current[1:]
				continue
			}
			if literalOptionAssignment(value, "-chdir") {
				current = current[1:]
				continue
			}
		case "kubectl":
			if kubectlBooleanGlobalOption(value) {
				current = current[1:]
				continue
			}
			if kubectlValueGlobalOption(value) {
				if len(current) < 2 || !current[1].static || !validKubectlGlobalOptionValue(value, current[1].value) {
					return nil, gap("unsupported_kubectl_global_option", "A kubectl global option is missing a literal argument.")
				}
				current = current[2:]
				continue
			}
			if kubectlAssignedGlobalOption(value) {
				current = current[1:]
				continue
			}
		case "docker":
			if dockerBooleanGlobalOption(value) {
				current = current[1:]
				continue
			}
			if dockerValueGlobalOption(value) {
				if len(current) < 2 || !current[1].static || !validDockerGlobalOptionValue(value, current[1].value) {
					return nil, gap("unsupported_docker_global_option", "A Docker global option is missing a literal argument.")
				}
				current = current[2:]
				continue
			}
			if dockerAssignedGlobalOption(value) {
				current = current[1:]
				continue
			}
		default:
			return args, nil
		}
		return nil, gap("unsupported_global_option", "A command global option is outside Ward classification.")
	}
	return current, nil
}

func literalOptionAssignment(value, name string) bool {
	return strings.HasPrefix(value, name+"=") && len(value) > len(name)+1
}

func validGitConfigOverride(value string) bool {
	key, _, _ := strings.Cut(value, "=")
	return validGitConfigKey(key)
}

func validGitConfigKey(key string) bool {
	parts := strings.Split(key, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || !asciiAlphaNumeric(rune(part[0])) {
			return false
		}
		for _, char := range part[1:] {
			if char != '-' && !asciiAlphaNumeric(char) {
				return false
			}
		}
	}
	return true
}

func asciiAlphaNumeric(char rune) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
}

func kubectlBooleanGlobalOption(value string) bool {
	name, assignedValue, assigned := strings.Cut(value, "=")
	switch name {
	case "--disable-compression", "--insecure-skip-tls-verify", "--match-server-version", "--warnings-as-errors":
		return !assigned || assignedValue == "true" || assignedValue == "false"
	default:
		return false
	}
}

func kubectlValueGlobalOption(value string) bool {
	switch value {
	case "--as", "--as-group", "--as-uid", "--cache-dir", "--certificate-authority", "--client-certificate",
		"--client-key", "--cluster", "--context", "--kubeconfig", "--namespace", "-n", "--profile",
		"--profile-output", "--request-timeout", "--server", "-s", "--tls-server-name", "--token", "--user",
		"--v", "--vmodule", "--log-flush-frequency":
		return true
	default:
		return false
	}
}

func kubectlAssignedGlobalOption(value string) bool {
	name, assignedValue, found := strings.Cut(value, "=")
	if !found || assignedValue == "" {
		return false
	}
	if kubectlValueGlobalOption(name) {
		return validKubectlGlobalOptionValue(name, assignedValue)
	}
	return kubectlBooleanGlobalOption(value)
}

func validKubectlGlobalOptionValue(name, value string) bool {
	if value == "" || !kubectlValueGlobalOption(name) {
		return false
	}
	switch name {
	case "--profile":
		switch strings.ToLower(value) {
		case "none", "cpu", "heap", "allocs", "goroutine", "threadcreate", "block", "mutex":
			return true
		default:
			return false
		}
	case "--request-timeout", "--log-flush-frequency":
		_, err := time.ParseDuration(value)
		return err == nil
	case "--v":
		for _, char := range value {
			if char < '0' || char > '9' {
				return false
			}
		}
		return true
	case "--vmodule":
		for _, entry := range strings.Split(value, ",") {
			pattern, level, found := strings.Cut(entry, "=")
			if !found || pattern == "" || level == "" || strings.ContainsAny(pattern, " \t\r\n") {
				return false
			}
			for _, char := range level {
				if char < '0' || char > '9' {
					return false
				}
			}
		}
	}
	return true
}

func dockerBooleanGlobalOption(value string) bool {
	name, assignedValue, assigned := strings.Cut(value, "=")
	switch name {
	case "--debug", "--tls", "--tlsverify":
		return !assigned || assignedValue == "true" || assignedValue == "false"
	case "-D":
		return !assigned
	default:
		return false
	}
}

func dockerValueGlobalOption(value string) bool {
	switch value {
	case "--config", "--context", "-c", "--host", "-H", "--log-level", "-l", "--tlscacert", "--tlscert", "--tlskey":
		return true
	default:
		return false
	}
}

func dockerAssignedGlobalOption(value string) bool {
	name, assignedValue, found := strings.Cut(value, "=")
	return found && validDockerGlobalOptionValue(name, assignedValue)
}

func validDockerGlobalOptionValue(name, value string) bool {
	if value == "" || !dockerValueGlobalOption(name) {
		return false
	}
	if name == "--log-level" || name == "-l" {
		switch strings.ToLower(value) {
		case "debug", "info", "warn", "error", "fatal":
			return true
		default:
			return false
		}
	}
	if name == "--host" || name == "-H" {
		for _, prefix := range []string{"unix://", "tcp://", "ssh://", "npipe://", "fd://"} {
			if strings.HasPrefix(strings.ToLower(value), prefix) && len(value) > len(prefix) {
				return true
			}
		}
		return false
	}
	return true
}

func (e *Evaluator) evaluateFindPaths(args []literalArg, cwd string) scanResult {
	result := scanResult{}
	deleteOperation := hasLiteral(args, "-delete")
	for _, arg := range args {
		if !arg.static {
			result.addGap(gap("dynamic_find_path", "A find search path contains runtime expansion or globbing."))
			continue
		}
		if strings.HasPrefix(arg.value, "-") || arg.value == "!" || arg.value == "(" {
			break
		}
		if ruleID, protected := e.matchProtectedPath(arg.value, cwd, deleteOperation); protected {
			return denied(ruleID, secretReason)
		}
	}
	return result
}

func hasFindCommandAction(args []literalArg) bool {
	for _, arg := range args {
		if !arg.static {
			continue
		}
		switch arg.value {
		case "-exec", "-execdir", "-ok", "-okdir":
			return true
		}
	}
	return false
}

func literalWord(word *syntax.Word) (string, bool) {
	if word == nil {
		return "", false
	}
	var builder strings.Builder
	for _, part := range word.Parts {
		value, static := literalPart(part, false)
		builder.WriteString(value)
		if !static {
			return builder.String(), false
		}
	}
	return builder.String(), true
}

func exactPWDWord(word *syntax.Word, cwd string) (string, bool) {
	if word == nil || strings.TrimSpace(cwd) == "" {
		return "", false
	}
	parts := make([]syntax.WordPart, 0, len(word.Parts))
	for _, part := range word.Parts {
		if quoted, ok := part.(*syntax.DblQuoted); ok && !quoted.Dollar {
			parts = append(parts, quoted.Parts...)
			continue
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 || !plainPWDParameter(parts[0]) {
		return "", false
	}
	var suffix strings.Builder
	for _, part := range parts[1:] {
		literal, ok := part.(*syntax.Lit)
		if !ok {
			return "", false
		}
		suffix.WriteString(literal.Value)
	}
	switch suffix.String() {
	case "", "/", "/.", "/./":
		return path.Clean(strings.ReplaceAll(cwd, `\`, "/")), true
	default:
		return "", false
	}
}

func plainPWDParameter(part syntax.WordPart) bool {
	parameter, ok := part.(*syntax.ParamExp)
	return ok && parameter.Param != nil && parameter.Param.Value == "PWD" &&
		parameter.Flags == nil && !parameter.Excl && !parameter.Length && !parameter.Width && !parameter.IsSet &&
		parameter.NestedParam == nil && parameter.Index == nil && len(parameter.Modifiers) == 0 &&
		parameter.Slice == nil && parameter.Repl == nil && parameter.Names == 0 && parameter.Exp == nil
}

func literalPart(part syntax.WordPart, quoted bool) (string, bool) {
	switch typed := part.(type) {
	case *syntax.Lit:
		if !quoted && strings.ContainsAny(typed.Value, "*?[") {
			return typed.Value, false
		}
		return typed.Value, true
	case *syntax.SglQuoted:
		return typed.Value, true
	case *syntax.DblQuoted:
		var builder strings.Builder
		for _, nested := range typed.Parts {
			value, static := literalPart(nested, true)
			builder.WriteString(value)
			if !static {
				return builder.String(), false
			}
		}
		return builder.String(), true
	default:
		return "", false
	}
}

func unwrapPOSIX(argv []literalArg, unwrapNohup bool) ([]literalArg, *contract.CoverageGap, bool) {
	current := argv
	for len(current) > 0 && current[0].static {
		switch posixExecutableBase(current[0].value) {
		case "env":
			i := 1
			for i < len(current) {
				if !current[i].static {
					return current, gap("dynamic_wrapper", "A command wrapper contains runtime expansion."), false
				}
				value := current[i].value
				if value == "--" {
					i++
					break
				}
				if isAssignment(value) || value == "-i" || value == "--ignore-environment" || value == "-0" || value == "--null" {
					i++
					continue
				}
				if value == "-u" || value == "--unset" || value == "-C" || value == "--chdir" {
					if i+1 >= len(current) || !current[i+1].static {
						return current, gap("complex_env_wrapper", "An env option argument is missing or dynamic."), false
					}
					i += 2
					continue
				}
				if (strings.HasPrefix(value, "--unset=") || strings.HasPrefix(value, "--chdir=")) && strings.Contains(value, "=") && !strings.HasSuffix(value, "=") {
					i++
					continue
				}
				if strings.HasPrefix(value, "-") {
					return current, gap("complex_env_wrapper", "An env option is outside Ward wrapper classification."), false
				}
				break
			}
			if i >= len(current) {
				return nil, nil, true
			}
			current = current[i:]
		case "command":
			if len(current) == 1 {
				return current, nil, false
			}
			i := 1
			if current[i].static && current[i].value == "--" {
				i++
			} else if current[i].static && current[i].value == "-p" {
				i++
			}
			if i >= len(current) || !current[i].static || strings.HasPrefix(current[i].value, "-") {
				return current, gap("complex_command_wrapper", "A command wrapper is outside Ward classification."), false
			}
			current = current[i:]
		case "builtin":
			return current, gap("builtin_dispatch", "A shell builtin dispatcher is outside Ward wrapper classification."), false
		case "nohup":
			if !unwrapNohup {
				return current, gap("nohup_stdin_semantics", "Nohup stdin behavior is outside interactive-session classification."), false
			}
			if len(current) == 1 {
				return current, nil, false
			}
			i := 1
			if current[i].static && current[i].value == "--" {
				i++
			}
			if i >= len(current) || !current[i].static || strings.HasPrefix(current[i].value, "-") {
				return current, gap("complex_nohup_wrapper", "A nohup wrapper is outside Ward classification."), false
			}
			current = current[i:]
		case "sudo":
			if len(current) == 1 {
				return current, nil, false
			}
			if current[1].static && current[1].value == "--" {
				current = current[2:]
				continue
			}
			if !current[1].static || strings.HasPrefix(current[1].value, "-") {
				return current, gap("complex_sudo_wrapper", "Sudo options are not interpreted by Ward."), false
			}
			current = current[1:]
		default:
			return current, nil, false
		}
	}
	return current, nil, false
}

func isAssignment(value string) bool {
	name, _, found := strings.Cut(value, "=")
	if !found || name == "" {
		return false
	}
	for i, char := range name {
		if !(char == '_' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || i > 0 && char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func executableBase(value string) string {
	base := strings.ToLower(path.Base(strings.ReplaceAll(value, `\`, "/")))
	return strings.TrimSuffix(base, ".exe")
}

func posixExecutableBase(value string) string {
	return path.Base(strings.ReplaceAll(value, `\`, "/"))
}

func nestedShellScript(base string, args []literalArg) (nested bool, script string, known bool) {
	if base != "bash" && base != "sh" && base != "zsh" {
		return false, "", false
	}
	parsed := parseShellInvocation(base, args)
	if parsed.hasCommand {
		return true, parsed.command, parsed.commandStatic
	}
	// A shell reading stdin or a file is intentionally outside the parser's
	// current coverage, including encoded-payload pipelines.
	return true, "", false
}

func isInterpreterPayload(base string, args []literalArg) bool {
	flag := ""
	switch {
	case isPythonExecutable(base):
		flag = "-c"
	case base == "ruby", base == "perl", base == "node", base == "bun":
		flag = "-e"
	default:
		return false
	}
	for _, arg := range args {
		if arg.static && arg.value == flag {
			return true
		}
	}
	return false
}

func isPythonExecutable(base string) bool {
	if base == "python" || base == "python3" {
		return true
	}
	if !strings.HasPrefix(base, "python3.") {
		return false
	}
	version := strings.TrimPrefix(base, "python3.")
	if version == "" {
		return false
	}
	for _, char := range version {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func isOpaqueCommandDispatcher(base string) bool {
	switch base {
	case "eval", "xargs", "parallel":
		return true
	default:
		return false
	}
}

func (e *Evaluator) matchAdditiveCommand(argv []literalArg, caseFold bool) (ruleID string, matched, ambiguous bool) {
	if len(argv) == 0 || !argv[0].static {
		return "", false, true
	}
	base := posixExecutableBase(argv[0].value)
	if caseFold {
		base = executableBase(argv[0].value)
	}
	for _, rule := range e.commandRules {
		executableMatch := base == rule.Executable
		if caseFold {
			executableMatch = strings.EqualFold(base, rule.Executable)
		}
		if !executableMatch || len(argv)-1 < len(rule.ArgsPrefix) {
			continue
		}
		match := true
		for i, expected := range rule.ArgsPrefix {
			actual := argv[i+1]
			if !actual.static {
				ambiguous = true
				match = false
				break
			}
			if actual.value != expected {
				match = false
				break
			}
		}
		if match {
			return rule.ID, true, ambiguous
		}
	}
	return "", false, ambiguous
}

func isFileAccessCommand(base string) bool {
	switch base {
	case "cat", "nl", "xxd", "head", "tail", "less", "more",
		"strings", "od", "hexdump", "base64", "cp", "mv",
		"scp", "install", "dd", "tee", "chmod", "chown", "touch",
		"truncate", "stat", "file", "realpath", "readlink":
		return true
	default:
		return false
	}
}

func (e *Evaluator) evaluateRsyncFileOptions(args []literalArg, cwd string) scanResult {
	result := scanResult{gap: gap("complex_file_operands", "Rsync filter and transfer operands are not fully classified.")}
	for _, arg := range args {
		if !arg.static {
			return result
		}
	}
	operands := make([]string, 0, len(args))
	optionsDone := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !arg.static {
			return result
		}
		value := arg.value
		if optionsDone || value == "-" || !strings.HasPrefix(value, "-") {
			operands = append(operands, value)
			continue
		}
		if value == "--" {
			optionsDone = true
			continue
		}
		if name, assigned, found := strings.Cut(value, "="); found {
			switch {
			case stringIn(name, rsyncPathValueOptions()):
				if assigned == "" {
					return result
				}
				if ruleID, protected := e.matchProtectedPath(assigned, cwd, false); protected {
					return denied(ruleID, secretReason)
				}
				continue
			case stringIn(name, rsyncNonPathValueOptions()):
				if assigned == "" {
					return result
				}
				if isRsyncRemoteShellOption(name) {
					if ruleID, protected := e.matchRsyncRemoteShellPath(assigned, cwd); protected {
						return denied(ruleID, secretReason)
					}
				}
				continue
			default:
				return result
			}
		}
		if stringIn(value, rsyncPathValueOptions()) || stringIn(value, rsyncNonPathValueOptions()) {
			if i+1 >= len(args) || !args[i+1].static || args[i+1].value == "" {
				return result
			}
			i++
			if stringIn(value, rsyncPathValueOptions()) {
				if ruleID, protected := e.matchProtectedPath(args[i].value, cwd, false); protected {
					return denied(ruleID, secretReason)
				}
			} else if isRsyncRemoteShellOption(value) {
				if ruleID, protected := e.matchRsyncRemoteShellPath(args[i].value, cwd); protected {
					return denied(ruleID, secretReason)
				}
			}
			continue
		}
		if name, assigned, attached := rsyncAttachedShortValue(value); attached {
			if assigned == "" {
				return result
			}
			if stringIn(name, rsyncPathValueOptions()) {
				if ruleID, protected := e.matchProtectedPath(assigned, cwd, false); protected {
					return denied(ruleID, secretReason)
				}
			} else if isRsyncRemoteShellOption(name) {
				if ruleID, protected := e.matchRsyncRemoteShellPath(assigned, cwd); protected {
					return denied(ruleID, secretReason)
				}
			}
			continue
		}
		if strings.HasPrefix(value, "--") {
			if !stringIn(value, rsyncBooleanOptions()) {
				return result
			}
			continue
		}
		if !rsyncShortFlagsOnly(value) {
			return result
		}
	}
	if len(operands) < 2 {
		return result
	}
	for _, candidate := range operands {
		if rsyncRemoteOperand(candidate) {
			continue
		}
		if ruleID, protected := e.matchProtectedPath(candidate, cwd, false); protected {
			return denied(ruleID, secretReason)
		}
	}
	return result
}

func rsyncAttachedShortValue(value string) (name, assigned string, ok bool) {
	if len(value) <= 2 || value[0] != '-' || value[1] == '-' {
		return "", "", false
	}
	for index, flag := range value[1:] {
		candidate := "-" + string(flag)
		if stringIn(candidate, rsyncPathValueOptions()) || stringIn(candidate, rsyncNonPathValueOptions()) {
			byteIndex := index + 2
			return candidate, strings.TrimPrefix(value[byteIndex:], "="), true
		}
		if !strings.ContainsRune("aAbcDdFghHiIJKklLmnopPqRrstuvWxXyz", flag) {
			return "", "", false
		}
	}
	return "", "", false
}

func isRsyncRemoteShellOption(value string) bool {
	return value == "-e" || value == "--rsh"
}

func (e *Evaluator) matchRsyncRemoteShellPath(value, cwd string) (string, bool) {
	if value == "" || strings.ContainsAny(value, " \t\r\n'\"`$;&|<>(){}") {
		return "", false
	}
	return e.matchProtectedPath(value, cwd, false)
}

func rsyncPathValueOptions() []string {
	return []string{
		"-T",
		"--backup-dir", "--compare-dest", "--copy-dest", "--exclude-from", "--files-from",
		"--include-from", "--link-dest", "--log-file", "--only-write-batch", "--partial-dir",
		"--password-file", "--read-batch", "--temp-dir", "--write-batch",
	}
}

func rsyncNonPathValueOptions() []string {
	return []string{
		"-B", "-e", "-f", "-M",
		"--block-size", "--bwlimit", "--checksum-choice", "--chmod", "--compress-choice",
		"--compress-level", "--contimeout", "--exclude", "--filter", "--groupmap", "--include",
		"--max-delete", "--max-size", "--min-size", "--out-format", "--port", "--remote-option",
		"--rsh", "--rsync-path", "--skip-compress", "--suffix", "--timeout", "--usermap",
	}
}

func rsyncBooleanOptions() []string {
	return []string{
		"--acls", "--append", "--append-verify", "--archive", "--backup", "--checksum",
		"--compress", "--copy-dirlinks", "--copy-links", "--copy-unsafe-links", "--delete",
		"--delete-after", "--delete-before", "--delete-delay", "--delete-during", "--delete-excluded",
		"--devices", "--dirs", "--dry-run", "--existing", "--fake-super", "--force", "--group",
		"--hard-links", "--human-readable", "--ignore-errors", "--ignore-existing", "--itemize-changes",
		"--keep-dirlinks", "--links", "--numeric-ids", "--one-file-system", "--owner", "--perms",
		"--preallocate", "--progress", "--protect-args", "--quiet", "--recursive", "--relative",
		"--remove-source-files", "--safe-links", "--sparse", "--specials", "--stats", "--times",
		"--update", "--verbose", "--whole-file", "--xattrs",
	}
}

func rsyncShortFlagsOnly(value string) bool {
	if len(value) < 2 || value[0] != '-' || value[1] == '-' {
		return false
	}
	for _, flag := range value[1:] {
		if !strings.ContainsRune("aAbcDdFghHiIJKklLmnopPqRrstuvWxXyz", flag) {
			return false
		}
	}
	return true
}

func rsyncRemoteOperand(value string) bool {
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "rsync://") {
		return true
	}
	colon := strings.IndexByte(value, ':')
	if colon <= 0 {
		return false
	}
	if colon == 1 && len(value) >= 3 && (value[2] == '/' || value[2] == '\\') {
		return false
	}
	return !strings.ContainsAny(value[:colon], "/\\")
}

func isPatternFileCommand(base string) bool {
	switch base {
	case "grep", "rg", "awk", "sed":
		return true
	default:
		return false
	}
}

func (e *Evaluator) evaluatePatternFileCommand(base string, args []literalArg, cwd string) scanResult {
	result := scanResult{gap: gap("complex_file_operands", "Pattern and input-file operands are not fully classified for this command.")}
	if base == "grep" || base == "rg" {
		if parsed, classified := parseReviewedPatternOperands(base, args); classified {
			for _, candidate := range append(parsed.patternFiles, parsed.paths...) {
				if ruleID, protected := e.matchProtectedPath(candidate, cwd, false); protected {
					return denied(ruleID, secretReason)
				}
			}
		}
	}
	return result
}

type reviewedPatternOperands struct {
	patternFiles []string
	paths        []string
}

func parseReviewedPatternOperands(base string, args []literalArg) (reviewedPatternOperands, bool) {
	parsed := reviewedPatternOperands{}
	positionals := make([]string, 0, len(args))
	optionsDone := false
	patternOption := false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !arg.static {
			return reviewedPatternOperands{}, false
		}
		value := arg.value
		if !optionsDone && value == "--" {
			optionsDone = true
			continue
		}
		if !optionsDone && value != "-" && strings.HasPrefix(value, "-") {
			if reviewedPatternBooleanOption(base, value) || reviewedPatternShortCluster(base, value) {
				continue
			}
			name, attached, option := reviewedPatternValueOption(base, value)
			if !option {
				return reviewedPatternOperands{}, false
			}
			candidate := attached
			if candidate == "" {
				if index+1 >= len(args) || !args[index+1].static {
					return reviewedPatternOperands{}, false
				}
				index++
				candidate = args[index].value
			}
			patternOption = true
			if name == "file" {
				parsed.patternFiles = append(parsed.patternFiles, candidate)
			}
			continue
		}
		positionals = append(positionals, value)
	}
	if patternOption {
		parsed.paths = positionals
		return parsed, true
	}
	if len(positionals) >= 2 {
		parsed.paths = positionals[1:]
	}
	return parsed, true
}

func reviewedPatternBooleanOption(base, value string) bool {
	if stringIn(value, []string{
		"-F", "--fixed-strings", "-H", "--with-filename", "-i", "--ignore-case",
		"-n", "--line-number", "-q", "--quiet", "-v", "--invert-match",
		"-w", "--word-regexp", "-x", "--line-regexp",
	}) {
		return true
	}
	switch base {
	case "grep":
		return stringIn(value, []string{"-h", "--no-filename", "-s", "--no-messages"})
	case "rg":
		return stringIn(value, []string{
			"-I", "--no-filename", "-s", "--case-sensitive", "-S", "--smart-case",
			"--hidden", "-U", "--multiline", "--multiline-dotall", "--no-ignore",
		})
	default:
		return false
	}
}

func reviewedPatternShortCluster(base, value string) bool {
	if len(value) < 3 || value[0] != '-' || value[1] == '-' {
		return false
	}
	allowed := "FHinqvwx"
	if base == "grep" {
		allowed += "hs"
	} else if base == "rg" {
		allowed += "ISsU"
	}
	for _, flag := range value[1:] {
		if !strings.ContainsRune(allowed, flag) {
			return false
		}
	}
	return true
}

func reviewedPatternValueOption(base, value string) (name, attached string, ok bool) {
	switch {
	case value == "-f" || value == "--file":
		return "file", "", true
	case strings.HasPrefix(value, "--file=") && len(value) > len("--file="):
		return "file", strings.TrimPrefix(value, "--file="), true
	case value == "-e" || value == "--regexp":
		return "regexp", "", true
	case strings.HasPrefix(value, "--regexp=") && len(value) > len("--regexp="):
		return "regexp", strings.TrimPrefix(value, "--regexp="), true
	}
	if len(value) > 2 && value[0] == '-' && value[1] != '-' {
		allowed := "FHinqvwx"
		if base == "grep" {
			allowed += "hs"
		} else if base == "rg" {
			allowed += "ISsU"
		}
		for index, flag := range value[1:] {
			if flag == 'f' || flag == 'e' {
				byteIndex := index + 2
				kind := "regexp"
				if flag == 'f' {
					kind = "file"
				}
				attached := value[byteIndex:]
				if base == "rg" {
					if attached == "=" {
						return "", "", false
					}
					attached = strings.TrimPrefix(attached, "=")
				}
				return kind, attached, true
			}
			if !strings.ContainsRune(allowed, flag) {
				return "", "", false
			}
		}
	}
	return "", "", false
}

func (e *Evaluator) evaluateDeleteTargets(args []literalArg, cwd string) scanResult {
	for _, arg := range args {
		if !arg.static || strings.HasPrefix(arg.value, "-") {
			continue
		}
		if ruleID, protected := e.matchProtectedPath(arg.value, cwd, true); protected {
			return denied(ruleID, secretReason)
		}
		if isProtectedDeleteTarget(arg.value) {
			return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
		}
	}
	return scanResult{}
}

func (e *Evaluator) evaluateMoveAncestors(args []literalArg, cwd string) scanResult {
	operands := make([]literalArg, 0, len(args))
	optionsDone := false
	for _, arg := range args {
		if !arg.static {
			return scanResult{gap: gap("dynamic_move_operand", "A move operand contains runtime expansion.")}
		}
		if !optionsDone && arg.value == "--" {
			optionsDone = true
			continue
		}
		if !optionsDone && strings.HasPrefix(arg.value, "-") {
			if stringIn(arg.value, []string{
				"-f", "--force", "-i", "--interactive", "-n", "--no-clobber",
				"-T", "--no-target-directory", "-v", "--verbose", "--strip-trailing-slashes", "-k",
			}) {
				continue
			}
			if arg.value == "-t" || arg.value == "--target-directory" {
				return e.evaluateMoveTargetDirectory(args, cwd)
			}
			if strings.HasPrefix(arg.value, "--target-directory=") && len(arg.value) > len("--target-directory=") {
				return e.evaluateMoveTargetDirectory(args, cwd)
			}
			return scanResult{gap: gap("complex_move_operands", "A move option is outside Ward source classification.")}
		}
		operands = append(operands, arg)
	}
	if len(operands) < 2 {
		return scanResult{}
	}
	for _, source := range operands[:len(operands)-1] {
		if ruleID, protected := e.matchProtectedPath(source.value, cwd, true); protected {
			return denied(ruleID, secretReason)
		}
	}
	return scanResult{}
}

func (e *Evaluator) evaluateMoveTargetDirectory(args []literalArg, cwd string) scanResult {
	optionsDone := false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !arg.static {
			return scanResult{gap: gap("dynamic_move_operand", "A move operand contains runtime expansion.")}
		}
		if !optionsDone && arg.value == "--" {
			optionsDone = true
			continue
		}
		if !optionsDone && strings.HasPrefix(arg.value, "-") {
			switch arg.value {
			case "-f", "--force", "-i", "--interactive", "-n", "--no-clobber", "-v", "--verbose", "--strip-trailing-slashes", "-k":
				continue
			case "-t", "--target-directory":
				if index+1 >= len(args) || !args[index+1].static || args[index+1].value == "" {
					return scanResult{gap: gap("complex_move_operands", "A move target directory is missing or dynamic.")}
				}
				index++
				continue
			default:
				if strings.HasPrefix(arg.value, "--target-directory=") && len(arg.value) > len("--target-directory=") {
					continue
				}
				return scanResult{gap: gap("complex_move_operands", "A move option is outside Ward source classification.")}
			}
		}
		if ruleID, protected := e.matchProtectedPath(arg.value, cwd, true); protected {
			return denied(ruleID, secretReason)
		}
	}
	return scanResult{}
}

func (e *Evaluator) secretTransferPath(base string, args []literalArg, cwd string) (string, bool) {
	switch base {
	case "curl":
		for i, arg := range args {
			if !arg.static {
				continue
			}
			value := arg.value
			if value == "-T" || value == "--upload-file" {
				if i+1 < len(args) && args[i+1].static {
					if ruleID, protected := e.matchProtectedPath(args[i+1].value, cwd, false); protected {
						return ruleID, true
					}
				}
			}
			if value == "-d" || value == "--data" || value == "--data-binary" || value == "--data-ascii" ||
				value == "--data-urlencode" || value == "--json" || value == "-F" || value == "--form" {
				if i+1 < len(args) && args[i+1].static {
					if candidate := transferCandidate(args[i+1].value); candidate != "" {
						if ruleID, protected := e.matchProtectedPath(candidate, cwd, false); protected {
							return ruleID, true
						}
					}
				}
			}
			if strings.HasPrefix(value, "--upload-file=") {
				if ruleID, protected := e.matchProtectedPath(strings.TrimPrefix(value, "--upload-file="), cwd, false); protected {
					return ruleID, true
				}
			}
			for _, prefix := range []string{"--data=", "--data-binary=", "--data-ascii=", "--data-urlencode=", "--json=", "--form="} {
				if strings.HasPrefix(value, prefix) {
					if candidate := transferCandidate(strings.TrimPrefix(value, prefix)); candidate != "" {
						if ruleID, protected := e.matchProtectedPath(candidate, cwd, false); protected {
							return ruleID, true
						}
					}
				}
			}
		}
	case "wget":
		for i, arg := range args {
			if !arg.static {
				continue
			}
			if arg.value == "--post-file" && i+1 < len(args) && args[i+1].static {
				if ruleID, protected := e.matchProtectedPath(args[i+1].value, cwd, false); protected {
					return ruleID, true
				}
			}
			if strings.HasPrefix(arg.value, "--post-file=") {
				if ruleID, protected := e.matchProtectedPath(strings.TrimPrefix(arg.value, "--post-file="), cwd, false); protected {
					return ruleID, true
				}
			}
		}
	}
	return "", false
}

func transferCandidate(value string) string {
	if before, _, found := strings.Cut(value, ";"); found {
		value = before
	}
	if _, after, found := strings.Cut(value, "@"); found {
		return after
	}
	if _, after, found := strings.Cut(value, "<"); found {
		return after
	}
	return ""
}

func catastrophicRM(args []literalArg, cwd string) bool {
	if !hasRecursiveRMFlag(args) {
		return false
	}
	for _, arg := range args {
		if !arg.static && isRootGlob(arg.value) {
			return true
		}
		if !arg.static || strings.HasPrefix(arg.value, "-") {
			continue
		}
		if isCatastrophicTarget(arg.value, cwd) {
			return true
		}
	}
	return false
}

func recursiveRMHasUnresolvedHome(args []literalArg) bool {
	if !hasRecursiveRMFlag(args) {
		return false
	}
	for _, arg := range args {
		if arg.static && strings.HasPrefix(arg.value, "~/") && arg.value != "~/" {
			return true
		}
	}
	return false
}

func hasRecursiveRMFlag(args []literalArg) bool {
	for _, arg := range args {
		if !arg.static {
			continue
		}
		if arg.value == "--recursive" || strings.HasPrefix(arg.value, "-") && !strings.HasPrefix(arg.value, "--") && strings.ContainsAny(arg.value[1:], "rR") {
			return true
		}
	}
	return false
}

func isRootGlob(value string) bool {
	switch value {
	case "/*", "/.*", "/.?*", "/.??*", "/?*", "/??*", "/{*,.*}", "/{.*,*}":
		return true
	default:
		return false
	}
}

func catastrophicFind(args []literalArg, cwd string) bool {
	deleteSeen := false
	for _, arg := range args {
		if arg.static && arg.value == "-delete" {
			deleteSeen = true
		}
	}
	if !deleteSeen || len(args) == 0 {
		return false
	}
	return args[0].static && isCatastrophicTarget(args[0].value, cwd)
}

func isCatastrophicTarget(value, cwd string) bool {
	normalized := path.Clean(strings.ReplaceAll(strings.TrimSpace(value), `\`, "/"))
	normalizedCWD := path.Clean(strings.ReplaceAll(strings.TrimSpace(cwd), `\`, "/"))
	switch normalized {
	case "/", ".", "..", "~", "~/", ".git":
		return true
	}
	if normalized == normalizedCWD || isProtectedDeleteTarget(normalized) {
		return true
	}
	if isCommonHomeRoot(normalized) {
		return true
	}
	resolved := normalized
	if !path.IsAbs(resolved) && !strings.HasPrefix(resolved, "~/") {
		resolved = path.Clean(path.Join(normalizedCWD, resolved))
	}
	if path.IsAbs(resolved) && !isCleanupTarget(resolved) {
		if !pathWithin(resolved, normalizedCWD) || pathWithin(normalizedCWD, resolved) {
			return true
		}
	}
	return false
}

func isProtectedDeleteTarget(value string) bool {
	normalized := strings.ToLower(path.Clean(strings.ReplaceAll(strings.TrimSpace(value), `\`, "/")))
	if normalized == ".git" || strings.HasPrefix(normalized, ".git/") || strings.Contains(normalized, "/.git/") || strings.HasSuffix(normalized, "/.git") {
		return true
	}
	return normalized == "~/.local/state/ward" || strings.HasPrefix(normalized, "~/.local/state/ward/") ||
		strings.Contains(normalized, "/.local/state/ward/") || strings.HasSuffix(normalized, "/.local/state/ward") ||
		strings.Contains(normalized, "/ward/state/v1/") || strings.HasSuffix(normalized, "/ward/state/v1")
}

func isCommonHomeRoot(value string) bool {
	parts := strings.Split(strings.Trim(value, "/"), "/")
	if len(parts) == 1 && parts[0] == "root" && strings.HasPrefix(value, "/") {
		return true
	}
	if len(parts) == 2 && strings.HasPrefix(value, "/") && (strings.EqualFold(parts[0], "home") || strings.EqualFold(parts[0], "users")) {
		return true
	}
	return len(parts) == 3 && len(parts[0]) == 2 && parts[0][1] == ':' && strings.EqualFold(parts[1], "users")
}

func isCleanupTarget(value string) bool {
	lower := strings.ToLower(path.Clean(value))
	if lower == "/tmp" || lower == "/private/tmp" || lower == "/var/tmp" {
		return true
	}
	for _, prefix := range []string{"/tmp/", "/private/tmp/", "/var/tmp/"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	for _, marker := range []string{"/.cache/", "/cache/", "/generated/", "/library/caches/", "/appdata/local/temp/"} {
		if strings.Contains(lower+"/", marker) {
			return true
		}
	}
	return false
}

func pathWithin(candidate, root string) bool {
	candidate = path.Clean(candidate)
	root = strings.TrimSuffix(path.Clean(root), "/")
	return candidate == root || strings.HasPrefix(candidate, root+"/")
}

func destructiveGit(args []literalArg) bool {
	if len(args) == 0 || !args[0].static {
		return false
	}
	subcommand := args[0].value
	switch subcommand {
	case "reset":
		return hasLiteral(args[1:], "--hard")
	case "clean":
		return hasForceFlag(args[1:]) && hasDirectoryFlag(args[1:]) &&
			!hasDryRunFlag(args[1:])
	case "push":
		return !hasDryRunFlag(args[1:]) &&
			(hasForceFlag(args[1:]) || hasLiteralPrefix(args[1:], "--force-with-lease") ||
				hasLiteral(args[1:], "--mirror") || hasForcedRefspec(args[1:]))
	default:
		return false
	}
}

func destructiveTerraform(args []literalArg) bool {
	if len(args) == 0 || !args[0].static {
		return false
	}
	if args[0].value == "destroy" {
		return true
	}
	if args[0].value != "apply" {
		return false
	}
	destroyMode := false
	seen := false
	for index := 1; index < len(args); index++ {
		arg := args[index]
		if !arg.static {
			return false
		}
		if arg.value == "--" {
			break
		}
		if arg.value == "-help" || arg.value == "--help" || arg.value == "-h" {
			return false
		}
		switch arg.value {
		case "-destroy", "-destroy=true":
			destroyMode, seen = true, true
		case "-destroy=false":
			destroyMode, seen = false, true
		default:
			if terraformApplyBooleanOption(arg.value) || terraformApplyAssignedOption(arg.value) {
				continue
			}
			if terraformApplyValueOption(arg.value) {
				if index+1 >= len(args) || !args[index+1].static || args[index+1].value == "" {
					return false
				}
				index++
				continue
			}
			if strings.HasPrefix(arg.value, "-") {
				return false
			}
			return seen && destroyMode
		}
	}
	return seen && destroyMode
}

func terraformApplyBooleanOption(value string) bool {
	return stringIn(value, []string{
		"-auto-approve", "-compact-warnings", "-input", "-json", "-lock", "-no-color", "-refresh",
	})
}

func terraformApplyValueOption(value string) bool {
	return stringIn(value, []string{
		"-backup", "-lock-timeout", "-parallelism", "-replace", "-state", "-state-out",
		"-target", "-var", "-var-file",
	})
}

func terraformApplyAssignedOption(value string) bool {
	name, assigned, found := strings.Cut(value, "=")
	if !found || assigned == "" {
		return false
	}
	if terraformApplyBooleanOption(name) {
		return assigned == "true" || assigned == "false"
	}
	return terraformApplyValueOption(name)
}

func hasForcedRefspec(args []literalArg) bool {
	for _, arg := range args {
		if arg.static && len(arg.value) > 1 && strings.HasPrefix(arg.value, "+") {
			return true
		}
	}
	return false
}

func hasDirectoryFlag(args []literalArg) bool {
	for _, arg := range args {
		if !arg.static {
			continue
		}
		if arg.value == "--directories" || arg.value == "-d" ||
			strings.HasPrefix(arg.value, "-") && !strings.HasPrefix(arg.value, "--") && strings.Contains(arg.value[1:], "d") {
			return true
		}
	}
	return false
}

func hasDryRunFlag(args []literalArg) bool {
	for _, arg := range args {
		if !arg.static {
			continue
		}
		if arg.value == "--dry-run" || arg.value == "-n" ||
			strings.HasPrefix(arg.value, "-") && !strings.HasPrefix(arg.value, "--") && strings.Contains(arg.value[1:], "n") {
			return true
		}
	}
	return false
}

func hasForceFlag(args []literalArg) bool {
	for _, arg := range args {
		if !arg.static {
			continue
		}
		if arg.value == "--force" || arg.value == "-f" || strings.HasPrefix(arg.value, "-") && !strings.HasPrefix(arg.value, "--") && strings.Contains(arg.value[1:], "f") {
			return true
		}
	}
	return false
}

func destructiveDocker(args []literalArg) (bool, *contract.CoverageGap) {
	if len(args) >= 2 && literalAt(args, 0, "compose") {
		return destructiveCompose(args[1:])
	}
	return false, nil
}

func destructiveCompose(args []literalArg) (bool, *contract.CoverageGap) {
	current := args
	dryRun := false
	for len(current) > 0 {
		if !current[0].static {
			return false, gap("dynamic_compose_option", "A Docker Compose option contains runtime expansion.")
		}
		switch value := current[0].value; {
		case composeValueOption(value):
			if len(current) < 2 || !current[1].static || !validComposeGlobalValue(value, current[1].value) {
				return false, gap("unsupported_compose_option", "A Docker Compose option is missing a literal argument.")
			}
			current = current[2:]
		case composeAssignedValueOption(value), composeAttachedShortValueOption(value):
			current = current[1:]
		case value == "--dry-run":
			dryRun = true
			current = current[1:]
		case strings.HasPrefix(value, "--dry-run="):
			parsed, valid := composeDryRunValue(strings.TrimPrefix(value, "--dry-run="))
			if !valid {
				return false, gap("unsupported_compose_option", "A Docker Compose dry-run value is outside Ward classification.")
			}
			dryRun = parsed
			current = current[1:]
		default:
			if strings.HasPrefix(value, "-") {
				return false, gap("unsupported_compose_option", "A Docker Compose option is outside Ward classification.")
			}
			if value != "down" {
				return false, nil
			}
			destructive, downGap := destructiveComposeDown(current[1:], dryRun)
			if downGap != nil {
				return false, downGap
			}
			return destructive, nil
		}
	}
	return false, nil
}

func composeValueOption(value string) bool {
	switch value {
	case "-f", "--file", "--env-file", "--profile", "--project-directory", "-p", "--project-name",
		"--ansi", "--parallel":
		return true
	default:
		return false
	}
}

func composeAssignedValueOption(value string) bool {
	for _, name := range []string{"--file", "--env-file", "--profile", "--project-directory", "--project-name", "--ansi", "--parallel"} {
		if strings.HasPrefix(value, name+"=") {
			return validComposeGlobalValue(name, strings.TrimPrefix(value, name+"="))
		}
	}
	return false
}

func validComposeGlobalValue(name, value string) bool {
	if value == "" {
		return false
	}
	switch name {
	case "--ansi":
		return value == "auto" || value == "always" || value == "never"
	case "--parallel":
		if value == "-1" {
			return true
		}
		for _, char := range value {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

func composeAttachedShortValueOption(value string) bool {
	return strings.HasPrefix(value, "-f") && len(value) > 2 || strings.HasPrefix(value, "-p") && len(value) > 2
}

func destructiveComposeDown(args []literalArg, dryRun bool) (bool, *contract.CoverageGap) {
	volumes := false
	for index := 0; index < len(args); index++ {
		if !args[index].static {
			return false, gap("dynamic_compose_option", "A Docker Compose down option contains runtime expansion.")
		}
		value := args[index].value
		switch value {
		case "-v", "--volumes":
			volumes = true
		case "--dry-run":
			dryRun = true
		case "--remove-orphans":
			continue
		case "-t", "--timeout", "--rmi":
			if index+1 >= len(args) || !args[index+1].static || !validComposeDownValue(value, args[index+1].value) {
				return false, gap("unsupported_compose_option", "A Docker Compose down option is missing a valid literal argument.")
			}
			index++
		default:
			name, assigned, found := strings.Cut(value, "=")
			if found && name == "--dry-run" {
				parsed, valid := composeDryRunValue(assigned)
				if !valid {
					return false, gap("unsupported_compose_option", "A Docker Compose dry-run value is outside Ward classification.")
				}
				dryRun = parsed
				continue
			}
			if found && (name == "--timeout" || name == "--rmi") && validComposeDownValue(name, assigned) {
				continue
			}
			if found && name == "--remove-orphans" && (assigned == "true" || assigned == "false") {
				continue
			}
			if strings.HasPrefix(value, "-t") && len(value) > 2 && validComposeDownValue("-t", strings.TrimPrefix(value, "-t")) {
				continue
			}
			if validComposeServiceName(value) {
				continue
			}
			return false, gap("unsupported_compose_option", "A Docker Compose down option is outside Ward classification.")
		}
	}
	return volumes && !dryRun, nil
}

func composeDryRunValue(value string) (bool, bool) {
	switch strings.ToLower(value) {
	case "true", "1":
		return true, true
	case "false", "0":
		return false, true
	default:
		return false, false
	}
}

func validComposeServiceName(value string) bool {
	if value == "" || !asciiAlphaNumeric(rune(value[0])) {
		return false
	}
	for _, char := range value[1:] {
		if !asciiAlphaNumeric(char) && char != '_' && char != '-' && char != '.' {
			return false
		}
	}
	return true
}

func validComposeDownValue(name, value string) bool {
	if value == "" {
		return false
	}
	if name == "--rmi" {
		return value == "all" || value == "local"
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func destructiveKubectl(args []literalArg) (bool, *contract.CoverageGap) {
	if len(args) < 2 || !literalAt(args, 0, "delete") {
		return false, nil
	}
	resourceType := ""
	optionsDone := false
	dryRun := false
	for index := 1; index < len(args); index++ {
		arg := args[index]
		if !arg.static {
			return false, gap("dynamic_kubectl_delete_option", "A kubectl delete argument contains runtime expansion.")
		}
		if !optionsDone && arg.value == "--" {
			optionsDone = true
			continue
		}
		if !optionsDone && strings.HasPrefix(arg.value, "-") {
			lower := strings.ToLower(arg.value)
			if lower == "--dry-run" {
				dryRun = true
				continue
			}
			if strings.HasPrefix(lower, "--dry-run=") {
				parsed, valid := kubectlDryRunValue(strings.TrimPrefix(lower, "--dry-run="))
				if !valid {
					return false, gap("unsupported_kubectl_delete_option", "A kubectl dry-run mode is outside Ward classification.")
				}
				dryRun = parsed
				continue
			}
			next, reviewed := reviewedKubectlDeleteOption(args, index)
			if !reviewed {
				return false, gap("unsupported_kubectl_delete_option", "A kubectl delete option is outside Ward classification.")
			}
			index = next - 1
			continue
		}
		if resourceType == "" {
			resourceType = strings.ToLower(arg.value)
		}
	}
	if dryRun {
		return false, nil
	}
	return resourceType == "namespace" || resourceType == "namespaces" || resourceType == "ns" ||
		strings.HasPrefix(resourceType, "namespace/") || strings.HasPrefix(resourceType, "namespaces/") || strings.HasPrefix(resourceType, "ns/"), nil
}

func kubectlDryRunValue(value string) (bool, bool) {
	switch strings.ToLower(value) {
	case "client", "server", "true", "1", "t":
		return true, true
	case "none", "false", "0", "f":
		return false, true
	default:
		return false, false
	}
}

func reviewedKubectlDeleteOption(args []literalArg, index int) (int, bool) {
	value := args[index].value
	if kubectlBooleanGlobalOption(value) || kubectlAssignedGlobalOption(value) {
		return index + 1, true
	}
	if kubectlValueGlobalOption(value) {
		if index+1 >= len(args) || !args[index+1].static ||
			!validKubectlGlobalOptionValue(value, args[index+1].value) {
			return index, false
		}
		return index + 2, true
	}
	if stringIn(value, []string{"--all", "--force", "--ignore-not-found", "--now", "--recursive", "-R", "--wait"}) {
		return index + 1, true
	}
	if name, assigned, found := strings.Cut(value, "="); found &&
		stringIn(name, []string{"--all", "--force", "--ignore-not-found", "--now", "--recursive", "--wait"}) &&
		(assigned == "true" || assigned == "false") {
		return index + 1, true
	}
	if stringIn(value, []string{
		"-f", "--filename", "--field-selector", "--grace-period", "-k", "--kustomize",
		"-l", "--selector", "-o", "--output", "--raw", "--timeout",
	}) {
		if index+1 >= len(args) || !args[index+1].static || args[index+1].value == "" {
			return index, false
		}
		return index + 2, true
	}
	for _, name := range []string{
		"--filename", "--field-selector", "--grace-period", "--kustomize",
		"--selector", "--output", "--raw", "--timeout",
	} {
		if literalOptionAssignment(value, name) {
			return index + 1, true
		}
	}
	return index, false
}

func containsDestructiveSQL(base string, args []literalArg) bool {
	switch base {
	case "psql", "mysql", "mariadb":
	default:
		return false
	}
	for _, arg := range args {
		if !arg.static {
			return false
		}
	}
	if hasSQLClientInformationalOption(base, args) {
		return false
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.value == "--" {
			break
		}
		var sql string
		if sqlClientValueOption(base, arg.value) {
			if i+1 >= len(args) {
				continue
			}
			if sqlCommandOption(base, arg.value) {
				sql = args[i+1].value
			}
			i++
		} else if name, assigned, found := strings.Cut(arg.value, "="); found && sqlClientValueOption(base, name) {
			if sqlCommandOption(base, name) {
				sql = assigned
			}
		} else if name, assigned, found := sqlClientAttachedValue(base, arg.value); found {
			if sqlCommandOption(base, name) {
				sql = assigned
			}
		}
		sql = strings.TrimSpace(sql)
		if sql != "" {
			mysqlDialect := base == "mysql" || base == "mariadb"
			statements, valid := splitLiteralSQLStatementsDialect(sql, mysqlDialect)
			if !valid {
				continue
			}
			if mysqlDialect {
				bodies, commentsValid := mysqlExecutableCommentBodies(sql)
				if !commentsValid {
					continue
				}
				for _, body := range bodies {
					bodyStatements, bodyValid := splitLiteralSQLStatementsDialect(body, true)
					if bodyValid {
						statements = append(statements, bodyStatements...)
					}
				}
			}
			for _, statement := range statements {
				if mysqlDialect && dropDatabaseMySQLSQL.MatchString(statement) ||
					!mysqlDialect && (dropDatabaseSQL.MatchString(statement) || dropSchemaCascadeSQL.MatchString(statement)) {
					return true
				}
			}
		}
	}
	return false
}

func sqlCommandOption(base, value string) bool {
	if base == "psql" {
		return value == "-c" || value == "--command"
	}
	return value == "-e" || value == "--execute"
}

func sqlClientAttachedValue(base, value string) (string, string, bool) {
	options := []string{"-c", "-d", "-f", "-F", "-h", "-L", "-o", "-p", "-P", "-R", "-T", "-U", "-v"}
	if base == "mysql" || base == "mariadb" {
		options = []string{"-D", "-e", "-h", "-P", "-S", "-u"}
	}
	for _, option := range options {
		if strings.HasPrefix(value, option) && len(value) > len(option) {
			return option, strings.TrimPrefix(value, option), true
		}
	}
	return "", "", false
}

func hasSQLClientInformationalOption(base string, args []literalArg) bool {
	for index := 0; index < len(args); index++ {
		value := args[index].value
		if value == "--" {
			return false
		}
		if sqlClientValueOption(base, value) {
			if index+1 < len(args) {
				index++
			}
			continue
		}
		if strings.Contains(value, "=") || sqlClientAttachedValueOption(base, value) {
			name, _, _ := strings.Cut(value, "=")
			if name == "--help" || name == "--version" {
				return true
			}
			continue
		}
		switch base {
		case "psql":
			if value == "--help" || value == "-?" || value == "--version" || value == "-V" {
				return true
			}
		case "mysql", "mariadb":
			if value == "--help" || value == "-?" || value == "--version" || value == "-V" || value == "-I" {
				return true
			}
		}
	}
	return false
}

func sqlClientValueOption(base, value string) bool {
	switch base {
	case "psql":
		return stringIn(value, []string{
			"-c", "--command", "-d", "--dbname", "-f", "--file", "-F", "--field-separator",
			"-h", "--host", "-L", "--log-file", "-o", "--output", "-p", "--port",
			"-P", "--pset", "-R", "--record-separator", "-T", "--table-attr",
			"-U", "--username", "-v", "--set",
		})
	case "mysql", "mariadb":
		return stringIn(value, []string{
			"-D", "--database", "-e", "--execute", "-h", "--host", "-P", "--port",
			"-S", "--socket", "-u", "--user", "--protocol", "--default-character-set",
			"--defaults-extra-file", "--defaults-file", "--login-path", "--ssl-ca", "--ssl-capath",
			"--ssl-cert", "--ssl-cipher", "--ssl-crl", "--ssl-crlpath", "--ssl-key",
			"--tls-ciphersuites", "--tls-version",
		})
	default:
		return false
	}
}

func sqlClientAttachedValueOption(base, value string) bool {
	for _, option := range []string{"-c", "-d", "-f", "-F", "-h", "-L", "-o", "-p", "-P", "-R", "-T", "-U", "-v"} {
		if base == "psql" && strings.HasPrefix(value, option) && len(value) > len(option) {
			return true
		}
	}
	for _, option := range []string{"-D", "-e", "-h", "-P", "-S", "-u"} {
		if (base == "mysql" || base == "mariadb") && strings.HasPrefix(value, option) && len(value) > len(option) {
			return true
		}
	}
	return false
}

func splitLiteralSQLStatements(input string) []string {
	statements, _ := splitLiteralSQLStatementsDialect(input, false)
	return statements
}

func splitLiteralSQLStatementsDialect(input string, hashComments bool) ([]string, bool) {
	statements := make([]string, 0, 2)
	var current strings.Builder
	var quote byte
	var dollarTag string
	lineComment := false
	blockDepth := 0
	flush := func() {
		statement := strings.TrimSpace(current.String())
		if statement != "" {
			statements = append(statements, statement)
		}
		current.Reset()
	}
	for index := 0; index < len(input); index++ {
		char := input[index]
		if lineComment {
			if char == '\n' || char == '\r' {
				lineComment = false
				current.WriteByte(' ')
			}
			continue
		}
		if blockDepth > 0 {
			if index+1 < len(input) && input[index:index+2] == "/*" {
				blockDepth++
				index++
				continue
			}
			if index+1 < len(input) && input[index:index+2] == "*/" {
				blockDepth--
				index++
				if blockDepth == 0 {
					current.WriteByte(' ')
				}
			}
			continue
		}
		if dollarTag != "" {
			if strings.HasPrefix(input[index:], dollarTag) {
				current.WriteString(dollarTag)
				index += len(dollarTag) - 1
				dollarTag = ""
			} else {
				current.WriteByte(char)
			}
			continue
		}
		if quote != 0 {
			current.WriteByte(char)
			if char == '\\' && index+1 < len(input) {
				current.WriteByte(input[index+1])
				index++
				continue
			}
			if char == quote {
				if index+1 < len(input) && input[index+1] == quote {
					current.WriteByte(input[index+1])
					index++
				} else {
					quote = 0
				}
			}
			continue
		}
		if index+1 < len(input) && input[index:index+2] == "/*" {
			blockDepth = 1
			index++
			continue
		}
		if index+1 < len(input) && input[index:index+2] == "--" {
			lineComment = true
			index++
			continue
		}
		if hashComments && char == '#' {
			lineComment = true
			continue
		}
		if char == '$' {
			if tag, ok := sqlDollarTagAt(input, index); ok {
				dollarTag = tag
				current.WriteString(tag)
				index += len(tag) - 1
				continue
			}
		}
		if char == '\'' || char == '"' || char == '`' {
			quote = char
			current.WriteByte(char)
			continue
		}
		if char == ';' {
			flush()
			continue
		}
		current.WriteByte(char)
	}
	if quote != 0 || dollarTag != "" || blockDepth != 0 {
		return nil, false
	}
	flush()
	return statements, true
}

func mysqlExecutableCommentBodies(input string) ([]string, bool) {
	bodies := make([]string, 0, 1)
	var quote byte
	lineComment := false
	for index := 0; index < len(input); index++ {
		char := input[index]
		if lineComment {
			if char == '\n' || char == '\r' {
				lineComment = false
			}
			continue
		}
		if quote != 0 {
			if char == '\\' && index+1 < len(input) {
				index++
				continue
			}
			if char == quote {
				if index+1 < len(input) && input[index+1] == quote {
					index++
				} else {
					quote = 0
				}
			}
			continue
		}
		if char == '\'' || char == '"' || char == '`' {
			quote = char
			continue
		}
		if char == '#' || index+1 < len(input) && input[index:index+2] == "--" {
			lineComment = true
			if char == '-' {
				index++
			}
			continue
		}
		markerLength := 0
		if strings.HasPrefix(input[index:], "/*!") {
			markerLength = 3
		} else if strings.HasPrefix(input[index:], "/*M!") {
			markerLength = 4
		}
		if markerLength > 0 {
			end := strings.Index(input[index+markerLength:], "*/")
			if end < 0 {
				return nil, false
			}
			body := strings.TrimSpace(input[index+markerLength : index+markerLength+end])
			body = strings.TrimLeft(body, "0123456789")
			body = strings.TrimSpace(body)
			if body != "" {
				bodies = append(bodies, body)
			}
			index += markerLength + end + 1
			continue
		}
		if strings.HasPrefix(input[index:], "/*") {
			end := strings.Index(input[index+2:], "*/")
			if end < 0 {
				return nil, false
			}
			index += end + 3
		}
	}
	return bodies, quote == 0
}

func sqlDollarTagAt(input string, index int) (string, bool) {
	if index >= len(input) || input[index] != '$' {
		return "", false
	}
	end := index + 1
	for end < len(input) {
		char := input[end]
		if char == '$' {
			return input[index : end+1], true
		}
		if !(char == '_' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return "", false
		}
		end++
	}
	return "", false
}

func literalOptionValue(args []literalArg, index int, names ...string) string {
	value := args[index].value
	for _, name := range names {
		if value == name {
			if index+1 < len(args) && args[index+1].static {
				return args[index+1].value
			}
			return ""
		}
		if strings.HasPrefix(value, name+"=") {
			return strings.TrimPrefix(value, name+"=")
		}
		if len(name) == 2 && strings.HasPrefix(value, name) && len(value) > len(name) {
			return strings.TrimPrefix(value, name)
		}
	}
	return ""
}

func hasLiteral(args []literalArg, expected string) bool {
	for _, arg := range args {
		if arg.static && arg.value == expected {
			return true
		}
	}
	return false
}

func hasLiteralPrefix(args []literalArg, prefix string) bool {
	for _, arg := range args {
		if arg.static && strings.HasPrefix(arg.value, prefix) {
			return true
		}
	}
	return false
}

func literalAt(args []literalArg, index int, expected string) bool {
	return index < len(args) && args[index].static && args[index].value == expected
}
