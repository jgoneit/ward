package evaluator

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/jgoneit/ward/internal/contract"
	"mvdan.cc/sh/v3/syntax"
)

const maxNestedShellDepth = 3

var (
	dropDatabaseSQL      = regexp.MustCompile(`(?i)^drop[[:space:]]+database[[:space:]]+(?:if[[:space:]]+exists[[:space:]]+)?(?:"[^"]+"|[a-z0-9_.-]+)(?:[[:space:]]+(?:with[[:space:]]*)?\([^;]*\))?[[:space:]]*;?$`)
	dropDatabaseMySQLSQL = regexp.MustCompile(`(?i)^drop[[:space:]]+database[[:space:]]+(?:if[[:space:]]+exists[[:space:]]+)?(?:` + "`[^`]+`" + `|[a-z0-9_.-]+)[[:space:]]*;?$`)
	dropSchemaCascadeSQL = regexp.MustCompile(
		`(?i)^drop[[:space:]]+schema[[:space:]]+(?:if[[:space:]]+exists[[:space:]]+)?` +
			`(?:"(?:[^"]|"")+"|[a-z_][a-z0-9_$]*)` +
			`(?:[[:space:]]*,[[:space:]]*(?:"(?:[^"]|"")+"|[a-z_][a-z0-9_$]*))*` +
			`[[:space:]]+cascade[[:space:]]*;?$`,
	)
)

type literalArg struct {
	value  string
	static bool
}

func (e *Evaluator) evaluatePOSIX(command, cwd string, depth int) scanResult {
	return e.evaluatePOSIXWithCWD(command, cwd, depth, true)
}

type posixCWDState struct {
	path  string
	known bool
	facts []posixPathFact
}

type posixPathFact struct {
	path   string
	exists bool
}

func (e *Evaluator) evaluatePOSIXWithCWD(command, cwd string, depth int, cwdKnown bool) scanResult {
	if depth > maxNestedShellDepth {
		return scanResult{gap: gap("nested_shell_limit", "Nested shell evaluation exceeded its bounded depth.")}
	}
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return scanResult{gap: gap("shell_parse_error", "The POSIX shell parser rejected the command.")}
	}
	pwdCall := singleSimpleCall(file)
	initialState := posixCWDState{path: cwd, known: cwdKnown}
	callStates := e.posixCallStates(file, initialState)

	result := scanResult{}
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil {
			return false
		}
		if result.deny != nil {
			return false
		}
		if _, ok := node.(*syntax.FuncDecl); ok {
			// A function declaration does not execute its body. A later invocation
			// appears as its own CallExpr and is evaluated independently.
			result.addGap(gap("shell_function", "A shell function body is not evaluated until invocation."))
			return false
		}
		switch typed := node.(type) {
		case *syntax.CallExpr:
			states, classified := callStates[typed]
			if !classified {
				states = []posixCWDState{initialState}
			}
			if len(states) == 0 {
				return true
			}
			for _, state := range states {
				result.merge(e.evaluatePOSIXCall(typed, state.path, depth, typed == pwdCall, !state.known))
				if result.deny != nil {
					break
				}
			}
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
			_ = value
		}
		return true
	})
	return result
}

func posixIntroducesCWDIsolation(node syntax.Node) bool {
	switch typed := node.(type) {
	case *syntax.Subshell, *syntax.CmdSubst:
		return true
	case *syntax.BinaryCmd:
		return typed.Op == syntax.Pipe || typed.Op == syntax.PipeAll
	default:
		return false
	}
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

type posixStateFlow struct {
	success []posixCWDState
	failure []posixCWDState
}

func (e *Evaluator) posixCallStates(file *syntax.File, initial posixCWDState) map[*syntax.CallExpr][]posixCWDState {
	states := make(map[*syntax.CallExpr][]posixCWDState)
	if file != nil {
		e.posixStmtListFlow(file.Stmts, []posixCWDState{initial}, states)
	}
	return states
}

func (e *Evaluator) posixStmtListFlow(statements []*syntax.Stmt, inputs []posixCWDState, calls map[*syntax.CallExpr][]posixCWDState) posixStateFlow {
	current := dedupePOSIXStates(inputs)
	flow := posixStateFlow{success: current, failure: current}
	for _, statement := range statements {
		flow = e.posixStmtFlow(statement, current, calls)
		current = unionPOSIXStates(flow.success, flow.failure)
	}
	return flow
}

func (e *Evaluator) posixStmtFlow(statement *syntax.Stmt, inputs []posixCWDState, calls map[*syntax.CallExpr][]posixCWDState) posixStateFlow {
	if statement == nil || statement.Cmd == nil {
		return posixStateFlow{success: inputs, failure: inputs}
	}
	flow := e.posixCommandFlow(statement.Cmd, inputs, calls)
	if statement.Negated {
		flow.success, flow.failure = flow.failure, flow.success
	}
	if statement.Background || statement.Coprocess || statement.Disown {
		return posixStateFlow{success: inputs, failure: inputs}
	}
	return flow
}

func (e *Evaluator) posixCommandFlow(command syntax.Command, inputs []posixCWDState, calls map[*syntax.CallExpr][]posixCWDState) posixStateFlow {
	switch typed := command.(type) {
	case *syntax.CallExpr:
		calls[typed] = unionPOSIXStates(calls[typed], inputs)
		e.recordNestedPOSIXCallStates(typed, inputs, calls)
		var success, failure []posixCWDState
		for _, state := range inputs {
			if posixCallChangesCWD(typed) {
				transition := e.posixCWDChangeFlow(typed, state)
				success = append(success, transition.success...)
				failure = append(failure, transition.failure...)
				continue
			}
			status := literalPOSIXCallStatus(typed)
			if status == 2 {
				continue
			}
			if status >= 0 {
				success = append(success, e.posixCallSuccessState(typed, state))
			}
			if status <= 0 {
				failure = append(failure, state)
			}
		}
		return posixStateFlow{success: dedupePOSIXStates(success), failure: dedupePOSIXStates(failure)}
	case *syntax.BinaryCmd:
		switch typed.Op {
		case syntax.AndStmt:
			left := e.posixStmtFlow(typed.X, inputs, calls)
			right := e.posixStmtFlow(typed.Y, left.success, calls)
			return posixStateFlow{success: right.success, failure: unionPOSIXStates(left.failure, right.failure)}
		case syntax.OrStmt:
			left := e.posixStmtFlow(typed.X, inputs, calls)
			right := e.posixStmtFlow(typed.Y, left.failure, calls)
			return posixStateFlow{success: unionPOSIXStates(left.success, right.success), failure: right.failure}
		case syntax.Pipe, syntax.PipeAll:
			e.posixStmtFlow(typed.X, inputs, calls)
			e.posixStmtFlow(typed.Y, inputs, calls)
			return posixStateFlow{success: inputs, failure: inputs}
		default:
			return posixStateFlow{success: inputs, failure: inputs}
		}
	case *syntax.Block:
		return e.posixStmtListFlow(typed.Stmts, inputs, calls)
	case *syntax.Subshell:
		e.posixStmtListFlow(typed.Stmts, inputs, calls)
		return posixStateFlow{success: inputs, failure: inputs}
	case *syntax.IfClause:
		condition := e.posixStmtListFlow(typed.Cond, inputs, calls)
		thenFlow := e.posixStmtListFlow(typed.Then, condition.success, calls)
		elseFlow := posixStateFlow{success: condition.failure, failure: condition.failure}
		if typed.Else != nil {
			elseFlow = e.posixCommandFlow(typed.Else, condition.failure, calls)
		}
		return posixStateFlow{
			success: unionPOSIXStates(thenFlow.success, elseFlow.success),
			failure: unionPOSIXStates(thenFlow.failure, elseFlow.failure),
		}
	case *syntax.WhileClause:
		condition := e.posixStmtListFlow(typed.Cond, inputs, calls)
		bodyInputs := condition.success
		if typed.Until {
			bodyInputs = condition.failure
		}
		body := e.posixStmtListFlow(typed.Do, bodyInputs, calls)
		all := unionPOSIXStates(inputs, body.success, body.failure)
		return posixStateFlow{success: all, failure: all}
	case *syntax.ForClause:
		body := e.posixStmtListFlow(typed.Do, inputs, calls)
		all := unionPOSIXStates(inputs, body.success, body.failure)
		return posixStateFlow{success: all, failure: all}
	case *syntax.CaseClause:
		all := append([]posixCWDState(nil), inputs...)
		for _, item := range typed.Items {
			itemFlow := e.posixStmtListFlow(item.Stmts, inputs, calls)
			all = unionPOSIXStates(all, itemFlow.success, itemFlow.failure)
		}
		return posixStateFlow{success: all, failure: all}
	case *syntax.TimeClause:
		return e.posixStmtFlow(typed.Stmt, inputs, calls)
	case *syntax.CoprocClause:
		e.posixStmtFlow(typed.Stmt, inputs, calls)
		return posixStateFlow{success: inputs, failure: inputs}
	case *syntax.FuncDecl:
		return posixStateFlow{success: inputs, failure: inputs}
	default:
		return posixStateFlow{success: inputs, failure: inputs}
	}
}

func (e *Evaluator) recordNestedPOSIXCallStates(root *syntax.CallExpr, inputs []posixCWDState, calls map[*syntax.CallExpr][]posixCWDState) {
	syntax.Walk(root, func(node syntax.Node) bool {
		switch typed := node.(type) {
		case *syntax.CallExpr:
			return typed == root
		case *syntax.CmdSubst:
			e.posixStmtListFlow(typed.Stmts, inputs, calls)
			return false
		case *syntax.ProcSubst:
			e.posixStmtListFlow(typed.Stmts, inputs, calls)
			return false
		default:
			return true
		}
	})
}

func literalPOSIXCallStatus(call *syntax.CallExpr) int {
	if call == nil || len(call.Args) == 0 {
		return 0
	}
	value, static := literalWord(call.Args[0])
	if !static {
		return 0
	}
	switch posixExecutableBase(value) {
	case "true", ":":
		return 1
	case "false":
		return -1
	case "exit":
		return 2
	default:
		return 0
	}
}

func posixCallChangesCWD(call *syntax.CallExpr) bool {
	if call == nil || len(call.Args) == 0 {
		return false
	}
	argv := make([]literalArg, len(call.Args))
	for index, word := range call.Args {
		argv[index].value, argv[index].static = literalWord(word)
	}
	unwrapped, _, envDump := unwrapPOSIX(argv, true)
	if envDump || len(unwrapped) == 0 || !unwrapped[0].static {
		return false
	}
	base := posixExecutableBase(unwrapped[0].value)
	if base == "builtin" && len(unwrapped) > 1 && unwrapped[1].static {
		base = unwrapped[1].value
	}
	return base == "cd" || base == "pushd" || base == "popd"
}

func unionPOSIXStates(groups ...[]posixCWDState) []posixCWDState {
	var combined []posixCWDState
	for _, group := range groups {
		combined = append(combined, group...)
	}
	return dedupePOSIXStates(combined)
}

func dedupePOSIXStates(states []posixCWDState) []posixCWDState {
	seen := make(map[string]struct{}, len(states))
	result := make([]posixCWDState, 0, len(states))
	for _, state := range states {
		key := state.path
		if !state.known {
			key = "?" + key
		}
		for _, fact := range state.facts {
			key += "\x00" + fact.path
			if fact.exists {
				key += "\x01"
			}
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, state)
	}
	return result
}

func (e *Evaluator) posixCWDChangeFlow(call *syntax.CallExpr, current posixCWDState) posixStateFlow {
	next := e.posixCallCWDState(call, current)
	if !next.known {
		if target, literal := e.posixLiteralCWDTarget(call, current); literal {
			if exists, known := e.posixPathFactValue(current.facts, target); known && exists {
				next.path, next.known = target, true
				return posixStateFlow{success: []posixCWDState{next}}
			}
			if e.boundaries.goos == runtime.GOOS {
				if info, err := os.Stat(filepath.FromSlash(current.path)); err != nil || !info.IsDir() {
					// Synthetic/cross-filesystem conformance paths cannot prove the
					// chdir failure. Preserve an unknown success branch so absolute
					// catastrophic targets remain classifiable.
					return posixStateFlow{success: []posixCWDState{next}}
				}
			}
			return posixStateFlow{failure: []posixCWDState{current}}
		}
		// Dynamic directory changes are deliberately not promoted to a denial.
		// They retain one unknown success state and leave the request to the Host.
		return posixStateFlow{success: []posixCWDState{next}}
	}
	if e.posixCWDTargetInvalidated(call, current, next.path) {
		return posixStateFlow{failure: []posixCWDState{current}}
	}
	return posixStateFlow{success: []posixCWDState{next}}
}

func (e *Evaluator) posixLiteralCWDTarget(call *syntax.CallExpr, current posixCWDState) (string, bool) {
	if call == nil || len(call.Args) < 2 {
		return "", false
	}
	argv := make([]literalArg, len(call.Args))
	for index, word := range call.Args {
		argv[index].value, argv[index].static = literalWord(word)
		if !argv[index].static {
			return "", false
		}
	}
	unwrapped, _, envDump := unwrapPOSIX(argv, true)
	if envDump || len(unwrapped) < 2 || !unwrapped[0].static {
		return "", false
	}
	base := posixExecutableBase(unwrapped[0].value)
	args := unwrapped[1:]
	if base == "builtin" && len(args) > 1 && args[0].static {
		base, args = args[0].value, args[1:]
	}
	if base != "cd" && base != "pushd" {
		return "", false
	}
	for _, arg := range args {
		if arg.value == "--" || strings.HasPrefix(arg.value, "-") {
			continue
		}
		if arg.value == "" || !current.known && !e.boundaries.isAbsoluteCandidate(arg.value) {
			return "", false
		}
		target := arg.value
		if !e.boundaries.isAbsoluteCandidate(target) {
			target = path.Join(current.path, target)
		}
		normalized, ok := normalizeAbsoluteBoundary(target, e.boundaries.goos)
		return normalized, ok
	}
	return "", false
}

func (e *Evaluator) posixPathFactValue(facts []posixPathFact, target string) (exists, known bool) {
	for index := len(facts) - 1; index >= 0; index-- {
		fact := facts[index]
		if e.boundaries.sameBoundaryObject(target, fact.path) {
			return fact.exists, true
		}
		if !fact.exists && e.boundaries.boundaryObjectContains(fact.path, target) {
			return false, true
		}
	}
	return false, false
}

func (e *Evaluator) posixCWDTargetInvalidated(call *syntax.CallExpr, current posixCWDState, target string) bool {
	if e.boundaries.sameBoundaryObject(target, current.path) {
		return false
	}
	for index := len(current.facts) - 1; index >= 0; index-- {
		fact := current.facts[index]
		if !e.boundaries.sameBoundaryObject(target, fact.path) && !e.boundaries.boundaryObjectContains(fact.path, target) {
			continue
		}
		if fact.exists && e.boundaries.sameBoundaryObject(target, fact.path) {
			return false
		}
		return !fact.exists
	}
	// A literal target that existed while the request was classified is treated
	// as the successful branch. A missing literal target preserves the original
	// CWD as the only high-confidence branch.
	if e.boundaries.goos == runtime.GOOS {
		info, err := os.Stat(filepath.FromSlash(target))
		return err != nil || !info.IsDir()
	}
	_ = call
	return false
}

func (e *Evaluator) posixCallSuccessState(call *syntax.CallExpr, current posixCWDState) posixCWDState {
	if call == nil || len(call.Args) == 0 {
		return current
	}
	argv := make([]literalArg, len(call.Args))
	for index, word := range call.Args {
		argv[index].value, argv[index].static = literalWord(word)
		if !argv[index].static {
			return current
		}
	}
	unwrapped, _, envDump := unwrapPOSIX(argv, true)
	if envDump || len(unwrapped) == 0 || !unwrapped[0].static {
		return current
	}
	base := posixExecutableBase(unwrapped[0].value)
	args := unwrapped[1:]
	var removed, created []string
	switch base {
	case "rm", "rmdir", "unlink":
		removed = e.posixStaticOperands(args, current, nil)
	case "mv":
		operands := e.posixStaticOperands(args, current, map[string]bool{"-t": true, "--target-directory": true})
		if len(operands) >= 2 {
			removed = operands[:len(operands)-1]
		}
	case "find":
		if hasLiteral(args, "-delete") && !findHasNarrowingExpression(args, e.boundaries.goos) {
			paths, _ := reviewedFindSearchPaths(args)
			removed = e.posixResolvedOperands(paths, current)
		}
	case "mkdir":
		created = e.posixStaticOperands(args, current, map[string]bool{"-m": true, "--mode": true, "-Z": true, "--context": true})
	}
	for _, target := range removed {
		current.facts = appendPathFact(current.facts, posixPathFact{path: target})
	}
	for _, target := range created {
		current.facts = appendPathFact(current.facts, posixPathFact{path: target, exists: true})
	}
	return current
}

func (e *Evaluator) posixStaticOperands(args []literalArg, current posixCWDState, valueOptions map[string]bool) []string {
	var operands []literalArg
	optionsDone := false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !arg.static {
			return nil
		}
		if !optionsDone && arg.value == "--" {
			optionsDone = true
			continue
		}
		if !optionsDone && strings.HasPrefix(arg.value, "-") && arg.value != "-" {
			if valueOptions != nil && valueOptions[arg.value] {
				index++
				if index >= len(args) || !args[index].static {
					return nil
				}
			}
			continue
		}
		operands = append(operands, arg)
	}
	return e.posixResolvedOperands(operands, current)
}

func (e *Evaluator) posixResolvedOperands(args []literalArg, current posixCWDState) []string {
	result := make([]string, 0, len(args))
	for _, arg := range args {
		if !arg.static || !current.known && !e.boundaries.isAbsoluteCandidate(arg.value) {
			return nil
		}
		target := arg.value
		if !e.boundaries.isAbsoluteCandidate(target) {
			target = path.Join(current.path, target)
		}
		normalized, ok := normalizeAbsoluteBoundary(target, e.boundaries.goos)
		if !ok {
			return nil
		}
		result = append(result, normalized)
	}
	return result
}

func appendPathFact(facts []posixPathFact, fact posixPathFact) []posixPathFact {
	copyOfFacts := append([]posixPathFact(nil), facts...)
	return append(copyOfFacts, fact)
}

func (e *Evaluator) posixCallCWDState(call *syntax.CallExpr, current posixCWDState) posixCWDState {
	if call == nil || len(call.Args) == 0 {
		return current
	}
	argv := make([]literalArg, len(call.Args))
	dynamicArgument := false
	for index, word := range call.Args {
		argv[index].value, argv[index].static = literalWord(word)
		if !argv[index].static {
			if index == 0 {
				return current
			}
			dynamicArgument = true
		}
	}
	if dynamicArgument {
		base := posixExecutableBase(argv[0].value)
		if base == "cd" || base == "pushd" || base == "popd" || base == "builtin" {
			return posixCWDState{path: current.path, known: false}
		}
		return current
	}
	unwrapped, _, envDump := unwrapPOSIX(argv, true)
	if envDump || len(unwrapped) == 0 || !unwrapped[0].static {
		return current
	}
	base := posixExecutableBase(unwrapped[0].value)
	args := unwrapped[1:]
	if base == "builtin" && len(unwrapped) > 1 && unwrapped[1].static {
		base = unwrapped[1].value
		args = unwrapped[2:]
	}
	if base == "popd" {
		return posixCWDState{path: current.path, known: false}
	}
	if base == "pushd" {
		if len(args) != 1 || !args[0].static || strings.HasPrefix(args[0].value, "+") || strings.HasPrefix(args[0].value, "-") {
			return posixCWDState{path: current.path, known: false}
		}
		if !current.known && !e.boundaries.isAbsoluteCandidate(args[0].value) {
			return posixCWDState{path: current.path, known: false}
		}
		resolved, known := e.boundaries.resolveKnownDirectory(current.path, args[0].value)
		if !known {
			return posixCWDState{path: current.path, known: false}
		}
		return posixCWDState{path: resolved, known: true}
	}
	if base != "cd" {
		return current
	}
	targetIndex := 0
	for targetIndex < len(args) {
		value := args[targetIndex].value
		if value == "--" {
			targetIndex++
			break
		}
		if value == "-L" || value == "-P" || value == "-e" || value == "-@" {
			targetIndex++
			continue
		}
		if strings.HasPrefix(value, "-") {
			return posixCWDState{path: current.path, known: false}
		}
		break
	}
	if targetIndex >= len(args) || len(args[targetIndex:]) != 1 || !args[targetIndex].static {
		return posixCWDState{path: current.path, known: false}
	}
	target := strings.TrimSpace(args[targetIndex].value)
	if target == "" {
		return posixCWDState{path: current.path, known: false}
	}
	if !current.known && !e.boundaries.isAbsoluteCandidate(target) {
		return posixCWDState{path: current.path, known: false}
	}
	resolved, known := e.boundaries.resolveKnownDirectory(current.path, target)
	if !known {
		return posixCWDState{path: current.path, known: false}
	}
	return posixCWDState{path: resolved, known: true}
}

func (e *Evaluator) posixWrapperCWDState(argv []literalArg, current posixCWDState) posixCWDState {
	if len(argv) == 0 || !argv[0].static || posixExecutableBase(argv[0].value) != "env" {
		return current
	}
	for index := 1; index < len(argv); index++ {
		arg := argv[index]
		if !arg.static {
			return posixCWDState{path: current.path, known: false}
		}
		value := arg.value
		if value == "--" {
			break
		}
		var target string
		switch {
		case value == "-C" || value == "--chdir":
			if index+1 >= len(argv) || !argv[index+1].static {
				return posixCWDState{path: current.path, known: false}
			}
			index++
			target = argv[index].value
		case strings.HasPrefix(value, "--chdir=") && len(value) > len("--chdir="):
			target = strings.TrimPrefix(value, "--chdir=")
		case isAssignment(value) || value == "-i" || value == "--ignore-environment" || value == "-0" || value == "--null":
			continue
		case value == "-u" || value == "--unset":
			index++
			continue
		case strings.HasPrefix(value, "--unset="):
			continue
		default:
			return current
		}
		if target == "" || !current.known && !e.boundaries.isAbsoluteCandidate(target) {
			current.known = false
			continue
		}
		resolved, known := e.boundaries.resolveKnownDirectory(current.path, target)
		if !known {
			current.known = false
			continue
		}
		current = posixCWDState{path: resolved, known: true}
	}
	return current
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
	case "sh", "dash":
		allowed = "aefnuvxilsc"
	case "zsh":
		allowed = "dfilnsvxXc"
	case "ksh", "mksh":
		allowed = "cl"
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

func stringIn(value string, candidates []string) bool {
	for _, candidate := range candidates {
		if value == candidate {
			return true
		}
	}
	return false
}

func (e *Evaluator) evaluatePOSIXCall(call *syntax.CallExpr, cwd string, depth int, resolvePWD, cwdUncertain bool) scanResult {
	if len(call.Args) == 0 {
		return scanResult{}
	}
	argv := make([]literalArg, len(call.Args))
	result := scanResult{}
	for i, word := range call.Args {
		argv[i].value, argv[i].static = literalWord(word)
		if resolved, exact := exactHomeWord(word, e.boundaries.home); exact {
			argv[i].value, argv[i].static = resolved, true
		}
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
	effectiveCWD := e.posixWrapperCWDState(argv, posixCWDState{path: cwd, known: !cwdUncertain})
	cwd, cwdUncertain = effectiveCWD.path, !effectiveCWD.known

	unwrapped, unwrapGap, envDump := unwrapPOSIX(argv, true)
	result.addGap(unwrapGap)
	if envDump {
		return result
	}
	if len(unwrapped) == 0 || !unwrapped[0].static {
		return result
	}
	base := posixExecutableBase(unwrapped[0].value)
	if knownInformationalInterpreterInvocation(base, unwrapped[1:]) {
		return result
	}
	if nested, script, known := nestedShellScript(base, unwrapped[1:]); nested {
		if !known {
			result.addGap(gap("dynamic_interpreter_payload", "A nested shell payload is not a static literal."))
			return result
		}
		result.merge(e.evaluatePOSIXWithCWD(script, cwd, depth+1, !cwdUncertain))
		return result
	}
	if isInterpreterPayload(base, unwrapped[1:]) {
		result.addGap(gap("interpreter_payload", "Embedded interpreter code is outside Ward command classification."))
	}
	if isOpaqueCommandDispatcher(base) {
		result.addGap(gap("opaque_command_dispatch", "A command dispatcher payload is outside Ward command classification."))
	}

	operationArgs, operationGap := unwrapOperationGlobalOptions(base, unwrapped[1:])
	result.addGap(operationGap)

	if base == "mv" {
		result.merge(e.evaluatePOSIXMoveAncestors(unwrapped[1:], cwd, cwdUncertain))
		if result.deny != nil {
			return result
		}
	}

	switch base {
	case "rm":
		if hasRMInformationalOption(unwrapped[1:]) {
			return result
		}
		result.merge(e.evaluateDeleteTargets(unwrapped[1:], cwd, cwdUncertain))
		if result.deny != nil {
			return result
		}
		if recursiveRMHasUnresolvedHome(unwrapped[1:]) {
			result.addGap(gap("unresolved_home_target", "A recursive deletion target uses unresolved home expansion."))
		}
		if e.catastrophicRM(unwrapped[1:], cwd, cwdUncertain) {
			return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
		}
	case "unlink", "rmdir":
		if hasSimpleInformationalOption(unwrapped[1:]) {
			return result
		}
		result.merge(e.evaluateDeleteTargets(unwrapped[1:], cwd, cwdUncertain))
		if result.deny != nil {
			return result
		}
		if base == "rmdir" && rmdirParentsEnabled(unwrapped[1:]) {
			result.merge(e.evaluateParentRemovalTargets(unwrapped[1:], cwd, cwdUncertain))
			if result.deny != nil {
				return result
			}
		}
	case "find":
		result.merge(e.evaluateFindPaths(unwrapped[1:], cwd, cwdUncertain))
		if result.deny != nil {
			return result
		}
		if hasFindCommandAction(unwrapped[1:]) {
			result.addGap(gap("find_command_action", "A find command action is outside Ward command classification."))
		}
	case "git":
		if literalAt(operationArgs, 0, "rm") {
			if gitSubcommandDryRun(operationArgs[1:]) {
				return result
			}
			result.merge(e.evaluateDeleteTargets(operationArgs[1:], cwd, cwdUncertain))
			if result.deny != nil {
				return result
			}
		}
		if literalAt(operationArgs, 0, "mv") {
			if gitSubcommandDryRun(operationArgs[1:]) {
				return result
			}
			result.merge(e.evaluateMoveAncestors(operationArgs[1:], cwd, cwdUncertain))
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

func hasSimpleInformationalOption(args []literalArg) bool {
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

func gitSubcommandDryRun(args []literalArg) bool {
	for _, arg := range args {
		if !arg.static {
			return false
		}
		if arg.value == "--" {
			return false
		}
		if arg.value == "-n" || arg.value == "--dry-run" {
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
				value == "--no-replace-objects" || value == "--bare" || value == "--no-lazy-fetch" || value == "--no-optional-locks" ||
				value == "--literal-pathspecs" || value == "--no-literal-pathspecs" || value == "--glob-pathspecs" || value == "--noglob-pathspecs" ||
				value == "--icase-pathspecs" || value == "--no-advice":
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
			case strings.HasPrefix(value, "--attr-source="):
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
			if kubectlAttachedGlobalOption(value) {
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
	firstDot := strings.Index(key, ".")
	lastDot := strings.LastIndex(key, ".")
	if firstDot > 0 && lastDot > firstDot {
		return validGitConfigPart(key[:firstDot]) && validGitConfigPart(key[lastDot+1:]) &&
			key[firstDot+1:lastDot] != "" && !strings.ContainsAny(key[firstDot+1:lastDot], "\x00\r\n")
	}
	return validGitConfigKey(key)
}

func validGitConfigPart(part string) bool {
	if part == "" || !asciiAlphaNumeric(rune(part[0])) {
		return false
	}
	for _, char := range part[1:] {
		if char != '-' && !asciiAlphaNumeric(char) {
			return false
		}
	}
	return true
}

func validGitConfigKey(key string) bool {
	parts := strings.Split(key, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if !validGitConfigPart(part) {
			return false
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
		if !assigned {
			return true
		}
		_, err := strconv.ParseBool(assignedValue)
		return err == nil
	default:
		return false
	}
}

func kubectlValueGlobalOption(value string) bool {
	switch value {
	case "--as", "--as-group", "--as-uid", "--cache-dir", "--certificate-authority", "--client-certificate",
		"--client-key", "--cluster", "--context", "--kubeconfig", "--kuberc", "--namespace", "-n", "--profile",
		"--profile-output", "--request-timeout", "--server", "-s", "--tls-server-name", "--token", "--user",
		"--v", "-v", "--vmodule", "--log-flush-frequency":
		return true
	default:
		return false
	}
}

func kubectlAssignedGlobalOption(value string) bool {
	name, assignedValue, found := strings.Cut(value, "=")
	if !found {
		return false
	}
	if kubectlValueGlobalOption(name) {
		return validKubectlGlobalOptionValue(name, assignedValue)
	}
	return kubectlBooleanGlobalOption(value)
}

func validKubectlGlobalOptionValue(name, value string) bool {
	if !kubectlValueGlobalOption(name) {
		return false
	}
	if value == "" {
		return name == "--namespace" || name == "-n" || name == "--profile-output"
	}
	switch name {
	case "--profile":
		switch strings.ToLower(value) {
		case "none", "cpu", "heap", "allocs", "goroutine", "threadcreate", "block", "mutex", "trace":
			return true
		default:
			return false
		}
	case "--request-timeout", "--log-flush-frequency":
		_, err := time.ParseDuration(value)
		return err == nil
	case "--v", "-v":
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

func kubectlAttachedGlobalOption(value string) bool {
	if len(value) <= 2 || value[0] != '-' || value[1] == '-' {
		return false
	}
	name := value[:2]
	assigned := strings.TrimPrefix(value[2:], "=")
	switch name {
	case "-n", "-s":
		return assigned != ""
	case "-v":
		return validKubectlGlobalOptionValue("-v", assigned)
	default:
		return false
	}
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

func (e *Evaluator) evaluateFindPaths(args []literalArg, cwd string, cwdUncertain bool) scanResult {
	result := scanResult{}
	deleteOperation := hasLiteral(args, "-delete")
	if deleteOperation && findHasNarrowingExpression(args, e.boundaries.goos) {
		result.addGap(gap("find_command_action", "A find selection expression narrows the delete operation."))
		return result
	}
	dereferenceCommandLine := findDereferencesCommandLine(args)
	paths, pathGap := reviewedFindSearchPaths(args)
	result.addGap(pathGap)
	for _, arg := range paths {
		if !arg.static {
			result.addGap(gap("dynamic_find_path", "A find search path contains runtime expansion or globbing."))
			continue
		}
		if deleteOperation {
			candidate, ambiguous := e.candidateAtCWD(arg.value, cwd, cwdUncertain)
			protected := false
			if !ambiguous {
				if dereferenceCommandLine {
					protected = e.boundaries.protectsDereferencedRecursiveDelete(candidate)
				} else {
					protected = e.boundaries.protectsRecursiveDelete(candidate)
				}
			}
			if ambiguous {
				result.addGap(gap("dynamic_path", "A relative find target depends on a prior current-directory change."))
			} else if protected {
				return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
			}
		}
	}
	return result
}

func findHasNarrowingExpression(args []literalArg, goos string) bool {
	index := 0
	for index < len(args) {
		if !args[index].static {
			return true
		}
		switch args[index].value {
		case "-H", "-L", "-P", "-E", "-X", "-x":
			index++
			continue
		case "-D":
			if index+1 >= len(args) || !args[index+1].static {
				return true
			}
			index += 2
			continue
		}
		if isGNUFindOptimizationOption(args[index].value) {
			index++
			continue
		}
		break
	}
	if index < len(args) && args[index].static && args[index].value == "--" {
		index++
	}
	for index < len(args) {
		arg := args[index]
		if !arg.static {
			return true
		}
		if strings.HasPrefix(arg.value, "-") || arg.value == "!" || arg.value == "(" {
			break
		}
		index++
	}
	mindepthNarrows := false
	for ; index < len(args); index++ {
		if !args[index].static {
			return true
		}
		switch args[index].value {
		case "-delete", "-depth":
			continue
		case "-mindepth":
			if index+1 >= len(args) || !args[index+1].static {
				return true
			}
			var valid bool
			mindepthNarrows, valid = findMindepthNarrows(args[index+1].value, goos)
			if !valid {
				return true
			}
			index++
			continue
		default:
			return true
		}
	}
	return mindepthNarrows
}

func findMindepthNarrows(value, goos string) (bool, bool) {
	if strings.HasPrefix(value, "+") {
		value = strings.TrimPrefix(value, "+")
	}
	if value == "" {
		return false, false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false, false
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		if goos == "darwin" {
			return false, true
		}
		return true, true
	}
	return parsed > 1, true
}

func findDereferencesCommandLine(args []literalArg) bool {
	dereference := false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !arg.static || arg.value == "--" {
			return dereference
		}
		switch arg.value {
		case "-H", "-L":
			dereference = true
		case "-P":
			dereference = false
		case "-E", "-X", "-x":
			continue
		case "-D":
			index++
		default:
			if !isGNUFindOptimizationOption(arg.value) {
				return dereference
			}
		}
	}
	return dereference
}

func reviewedFindSearchPaths(args []literalArg) ([]literalArg, *contract.CoverageGap) {
	index := 0
	for index < len(args) {
		if !args[index].static {
			return nil, gap("dynamic_find_path", "A find search path contains runtime expansion or globbing.")
		}
		switch args[index].value {
		case "-H", "-L", "-P", "-E", "-X", "-x":
			index++
			continue
		case "-D":
			if index+1 >= len(args) || !args[index+1].static || args[index+1].value == "" {
				return nil, gap("complex_find_options", "A find debug option is missing its literal value.")
			}
			index += 2
			continue
		}
		if isGNUFindOptimizationOption(args[index].value) {
			index++
			continue
		}
		break
	}
	if index < len(args) && args[index].static && args[index].value == "--" {
		index++
	}
	paths := make([]literalArg, 0, len(args)-index)
	for ; index < len(args); index++ {
		arg := args[index]
		if !arg.static {
			return paths, gap("dynamic_find_path", "A find search path contains runtime expansion or globbing.")
		}
		if strings.HasPrefix(arg.value, "-") || arg.value == "!" || arg.value == "(" {
			break
		}
		paths = append(paths, arg)
	}
	return paths, nil
}

func isGNUFindOptimizationOption(value string) bool {
	if len(value) != 3 || !strings.HasPrefix(value, "-O") {
		return false
	}
	return value[2] >= '0' && value[2] <= '3'
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

func exactHomeWord(word *syntax.Word, home string) (string, bool) {
	if word == nil || len(word.Parts) != 1 || home == "" {
		return "", false
	}
	literal, ok := word.Parts[0].(*syntax.Lit)
	if !ok {
		return "", false
	}
	switch literal.Value {
	case "~", "~/", "~/.", "~/./":
		return home, true
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
		case "exec":
			i := 1
			for i < len(current) {
				if !current[i].static {
					return current, gap("dynamic_wrapper", "An exec wrapper contains runtime expansion."), false
				}
				value := current[i].value
				if value == "--" {
					i++
					break
				}
				switch value {
				case "-c", "-l":
					i++
					continue
				case "-a":
					if i+1 >= len(current) || !current[i+1].static {
						return current, gap("complex_command_wrapper", "An exec argv-zero override is missing or dynamic."), false
					}
					i += 2
					continue
				}
				if strings.HasPrefix(value, "-") {
					return current, gap("complex_command_wrapper", "An exec option is outside Ward wrapper classification."), false
				}
				break
			}
			if i >= len(current) {
				return nil, nil, true
			}
			if !current[i].static || strings.HasPrefix(current[i].value, "-") {
				return current, gap("complex_command_wrapper", "An exec command is outside Ward wrapper classification."), false
			}
			current = current[i:]
		case "builtin":
			return current, gap("builtin_dispatch", "A shell builtin dispatcher is outside Ward wrapper classification."), false
		case "busybox":
			if len(current) == 1 {
				return current, nil, false
			}
			i := 1
			if current[i].static && current[i].value == "--" {
				i++
			}
			if i >= len(current) || !current[i].static || strings.HasPrefix(current[i].value, "-") {
				return current, gap("complex_command_wrapper", "A BusyBox applet is outside Ward wrapper classification."), false
			}
			current = current[i:]
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
		case "timeout":
			i := 1
			for i < len(current) {
				if !current[i].static {
					return current, gap("dynamic_wrapper", "A timeout wrapper contains runtime expansion."), false
				}
				value := current[i].value
				if value == "--" {
					i++
					break
				}
				if value == "--preserve-status" || value == "--foreground" || value == "--verbose" {
					i++
					continue
				}
				if value == "-s" || value == "--signal" || value == "-k" || value == "--kill-after" {
					if i+1 >= len(current) || !current[i+1].static {
						return current, gap("complex_timeout_wrapper", "A timeout option value is missing or dynamic."), false
					}
					i += 2
					continue
				}
				if strings.HasPrefix(value, "--signal=") || strings.HasPrefix(value, "--kill-after=") {
					i++
					continue
				}
				break
			}
			if i >= len(current) || !current[i].static || !reviewedTimeoutDuration(current[i].value) {
				return current, gap("complex_timeout_wrapper", "A timeout duration is missing or outside Ward classification."), false
			}
			i++
			if i >= len(current) {
				return current, nil, false
			}
			current = current[i:]
		case "nice":
			i := 1
			if i < len(current) && current[i].static && current[i].value == "--" {
				i++
			} else if i < len(current) && current[i].static && (current[i].value == "-n" || current[i].value == "--adjustment") {
				if i+1 >= len(current) || !current[i+1].static || !signedDecimal(current[i+1].value) {
					return current, gap("complex_nice_wrapper", "A nice adjustment is missing or invalid."), false
				}
				i += 2
			} else if i < len(current) && current[i].static && strings.HasPrefix(current[i].value, "--adjustment=") {
				if !signedDecimal(strings.TrimPrefix(current[i].value, "--adjustment=")) {
					return current, gap("complex_nice_wrapper", "A nice adjustment is invalid."), false
				}
				i++
			} else if i < len(current) && current[i].static && len(current[i].value) > 1 && current[i].value[0] == '-' && signedDecimal(current[i].value) {
				i++
			}
			if i >= len(current) {
				return current, nil, false
			}
			current = current[i:]
		case "setsid":
			i := 1
			for i < len(current) && current[i].static {
				if current[i].value == "--" {
					i++
					break
				}
				if current[i].value == "-f" || current[i].value == "--fork" || current[i].value == "-w" || current[i].value == "--wait" || current[i].value == "-c" || current[i].value == "--ctty" {
					i++
					continue
				}
				break
			}
			if i >= len(current) {
				return current, nil, false
			}
			if !current[i].static || strings.HasPrefix(current[i].value, "-") {
				return current, gap("complex_setsid_wrapper", "A setsid wrapper is outside Ward classification."), false
			}
			current = current[i:]
		case "time":
			i := 1
			if i < len(current) && current[i].static && (current[i].value == "--" || current[i].value == "-p" || current[i].value == "--portability") {
				i++
			}
			if i >= len(current) {
				return current, nil, false
			}
			if !current[i].static || strings.HasPrefix(current[i].value, "-") {
				return current, gap("complex_time_wrapper", "A time wrapper is outside Ward classification."), false
			}
			current = current[i:]
		case "sudo":
			if len(current) == 1 {
				return current, nil, false
			}
			i := 1
			for i < len(current) {
				if !current[i].static {
					return current, gap("complex_sudo_wrapper", "A sudo option contains runtime expansion."), false
				}
				value := current[i].value
				if value == "--" {
					i++
					break
				}
				if isAssignment(value) || value == "-n" || value == "--non-interactive" {
					i++
					continue
				}
				if value == "-u" || value == "--user" {
					if i+1 >= len(current) || !current[i+1].static {
						return current, gap("complex_sudo_wrapper", "A sudo user option is missing or dynamic."), false
					}
					i += 2
					continue
				}
				if strings.HasPrefix(value, "--user=") && len(value) > len("--user=") {
					i++
					continue
				}
				if strings.HasPrefix(value, "-") {
					return current, gap("complex_sudo_wrapper", "Sudo options are outside Ward wrapper classification."), false
				}
				break
			}
			if i >= len(current) {
				return current, nil, false
			}
			current = current[i:]
		default:
			return current, nil, false
		}
	}
	return current, nil, false
}

func reviewedTimeoutDuration(value string) bool {
	if value == "" {
		return false
	}
	digits := 0
	dotSeen := false
	for index, char := range value {
		if char >= '0' && char <= '9' {
			digits++
			continue
		}
		if char == '.' && !dotSeen && index > 0 {
			dotSeen = true
			continue
		}
		return index == len(value)-1 && digits > 0 && strings.ContainsRune("smhd", char)
	}
	return digits > 0
}

func signedDecimal(value string) bool {
	if value == "" {
		return false
	}
	if value[0] == '+' || value[0] == '-' {
		value = value[1:]
	}
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
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
	if base != "bash" && base != "sh" && base != "zsh" && base != "dash" && base != "ksh" && base != "mksh" {
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

func (e *Evaluator) evaluateDeleteTargets(args []literalArg, cwd string, cwdUncertain bool) scanResult {
	result := scanResult{}
	optionsDone := false
	for _, arg := range args {
		if !arg.static {
			continue
		}
		if !optionsDone && arg.value == "--" {
			optionsDone = true
			continue
		}
		if !optionsDone && strings.HasPrefix(arg.value, "-") {
			continue
		}
		protected, ambiguous := e.classifyCriticalMutationTarget(arg.value, cwd, cwdUncertain)
		if ambiguous {
			result.addGap(gap("dynamic_path", "A relative deletion target depends on a prior current-directory change."))
			continue
		}
		if protected {
			return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
		}
	}
	return result
}

func (e *Evaluator) evaluateParentRemovalTargets(args []literalArg, cwd string, cwdUncertain bool) scanResult {
	result := scanResult{}
	optionsDone := false
	for _, arg := range args {
		if !arg.static {
			result.addGap(gap("dynamic_path", "A parent-removal target contains runtime expansion."))
			continue
		}
		if !optionsDone && arg.value == "--" {
			optionsDone = true
			continue
		}
		if !optionsDone && strings.HasPrefix(arg.value, "-") {
			continue
		}
		candidate, ambiguous := e.candidateAtCWD(arg.value, cwd, cwdUncertain)
		if ambiguous {
			result.addGap(gap("dynamic_path", "A relative parent-removal target depends on a prior current-directory change."))
			continue
		}
		cleanedOperand := path.Clean(strings.ReplaceAll(arg.value, `\`, "/"))
		reachesParent := e.boundaries.isAbsoluteCandidate(arg.value) || cleanedOperand == ".." || strings.HasPrefix(cleanedOperand, "../")
		protected := e.boundaries.protectsCriticalMetadata(candidate)
		if reachesParent {
			protected = e.boundaries.protectsParentRemoval(candidate)
		}
		if protected {
			return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
		}
	}
	return result
}

func rmdirParentsEnabled(args []literalArg) bool {
	parents := false
	for _, arg := range args {
		if !arg.static {
			return false
		}
		if arg.value == "--" {
			break
		}
		if !strings.HasPrefix(arg.value, "-") || arg.value == "-" {
			continue
		}
		switch arg.value {
		case "-p", "--parents":
			parents = true
		case "-v", "--verbose", "--ignore-fail-on-non-empty":
			continue
		default:
			if strings.HasPrefix(arg.value, "--") {
				return false
			}
			for _, flag := range arg.value[1:] {
				if flag == 'p' {
					parents = true
				} else if flag != 'v' {
					return false
				}
			}
		}
	}
	return parents
}

func (e *Evaluator) evaluateMoveAncestors(args []literalArg, cwd string, cwdUncertain bool) scanResult {
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
				return e.evaluateMoveTargetDirectory(args, cwd, cwdUncertain)
			}
			if strings.HasPrefix(arg.value, "--target-directory=") && len(arg.value) > len("--target-directory=") {
				return e.evaluateMoveTargetDirectory(args, cwd, cwdUncertain)
			}
			return scanResult{gap: gap("complex_move_operands", "A move option is outside Ward source classification.")}
		}
		operands = append(operands, arg)
	}
	if len(operands) < 2 {
		return scanResult{}
	}
	result := scanResult{}
	for _, source := range operands[:len(operands)-1] {
		protected, ambiguous := e.classifyCriticalRelocationTarget(source.value, cwd, cwdUncertain)
		if ambiguous {
			result.addGap(gap("dynamic_path", "A relative move source depends on a prior current-directory change."))
			continue
		}
		if protected {
			return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
		}
	}
	return result
}

type gnuMoveOperands struct {
	sources              []string
	exchangeDestinations []string
}

func (e *Evaluator) evaluatePOSIXMoveAncestors(args []literalArg, cwd string, cwdUncertain bool) scanResult {
	if e.boundaries.goos != "linux" {
		return e.evaluateMoveAncestors(args, cwd, cwdUncertain)
	}
	parsed, ok := reviewedGNUmoveOperands(args)
	if !ok {
		return scanResult{gap: gap("complex_move_operands", "A move option is outside Ward source classification.")}
	}
	result := scanResult{}
	for _, candidate := range append(parsed.sources, parsed.exchangeDestinations...) {
		protected, ambiguous := e.classifyCriticalRelocationTarget(candidate, cwd, cwdUncertain)
		if ambiguous {
			result.addGap(gap("dynamic_path", "A relative move source depends on a prior current-directory change."))
			continue
		}
		if protected {
			return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
		}
	}
	return result
}

func reviewedGNUmoveOperands(args []literalArg) (gnuMoveOperands, bool) {
	operands := make([]string, 0, len(args))
	optionsDone := false
	targetDirectory := ""
	targetDirectorySeen := false
	noTargetDirectory := false
	exchange := false
	backup := false
	noClobber := false
	updateMode := ""

	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !arg.static {
			return gnuMoveOperands{}, false
		}
		value := arg.value
		if !optionsDone && value == "--" {
			optionsDone = true
			continue
		}
		if optionsDone || !strings.HasPrefix(value, "-") || value == "-" {
			operands = append(operands, value)
			continue
		}

		switch value {
		case "-f", "--force":
			noClobber = false
		case "-i", "--interactive":
			noClobber = false
		case "-n", "--no-clobber":
			noClobber = true
		case "-b", "--backup":
			backup = true
		case "-u", "--update":
			updateMode = "older"
		case "-T", "--no-target-directory":
			noTargetDirectory = true
		case "--exchange":
			exchange = true
		case "-v", "--verbose", "--debug", "--strip-trailing-slashes", "-Z", "--context", "--no-copy":
			continue
		case "-t", "--target-directory", "--target-d":
			if targetDirectorySeen || index+1 >= len(args) || !args[index+1].static || args[index+1].value == "" {
				return gnuMoveOperands{}, false
			}
			targetDirectory, targetDirectorySeen = args[index+1].value, true
			index++
		case "-S", "--suffix":
			if index+1 >= len(args) || !args[index+1].static {
				return gnuMoveOperands{}, false
			}
			index++
		default:
			if gnuMoveTargetDirectoryOption(value) {
				if targetDirectorySeen || index+1 >= len(args) || !args[index+1].static || args[index+1].value == "" {
					return gnuMoveOperands{}, false
				}
				targetDirectory, targetDirectorySeen = args[index+1].value, true
				index++
				continue
			}
			name, assigned, found := strings.Cut(value, "=")
			switch {
			case found && gnuMoveTargetDirectoryOption(name):
				if targetDirectorySeen || assigned == "" {
					return gnuMoveOperands{}, false
				}
				targetDirectory, targetDirectorySeen = assigned, true
			case found && name == "--backup":
				if !validGNUmoveBackupControl(assigned) {
					return gnuMoveOperands{}, false
				}
				backup = true
			case found && name == "--suffix":
				// GNU mv accepts an explicitly empty suffix.
				continue
			case found && name == "--update":
				mode, valid := gnuMoveUpdateMode(assigned)
				if !valid {
					return gnuMoveOperands{}, false
				}
				updateMode = mode
			case found && name == "--context":
				// --context is a switch; GNU mv rejects every assigned form.
				return gnuMoveOperands{}, false
			default:
				consumed, shortBackup, shortNoClobber, shortNoTarget, shortUpdate, valid := parseGNUmoveShortOptions(value)
				if !valid {
					return gnuMoveOperands{}, false
				}
				if shortBackup {
					backup = true
				}
				if shortNoClobber != nil {
					noClobber = *shortNoClobber
				}
				noTargetDirectory = noTargetDirectory || shortNoTarget
				if shortUpdate != "" {
					updateMode = shortUpdate
				}
				if consumed != "" {
					switch consumed {
					case "target-directory":
						if targetDirectorySeen {
							return gnuMoveOperands{}, false
						}
						shortValue := gnuMoveAttachedShortValue(value, 't')
						if shortValue == "" {
							if index+1 >= len(args) || !args[index+1].static || args[index+1].value == "" {
								return gnuMoveOperands{}, false
							}
							shortValue = args[index+1].value
							index++
						}
						targetDirectory, targetDirectorySeen = shortValue, true
					case "suffix":
						if gnuMoveAttachedShortValue(value, 'S') == "" {
							if index+1 >= len(args) || !args[index+1].static {
								return gnuMoveOperands{}, false
							}
							index++
						}
					}
				}
			}
		}
	}

	if targetDirectorySeen && noTargetDirectory || backup && exchange || backup && (noClobber || updateMode == "none") {
		return gnuMoveOperands{}, false
	}
	parsed := gnuMoveOperands{}
	switch {
	case exchange && targetDirectorySeen:
		if len(operands) == 0 {
			return gnuMoveOperands{}, false
		}
		parsed.sources = append(parsed.sources, operands...)
		for _, source := range operands {
			base := path.Base(strings.TrimRight(strings.ReplaceAll(source, `\`, "/"), "/"))
			if base == "." || base == "/" || base == "" {
				return gnuMoveOperands{}, false
			}
			parsed.exchangeDestinations = append(parsed.exchangeDestinations, path.Join(targetDirectory, base))
		}
	case exchange:
		if len(operands) != 2 {
			return gnuMoveOperands{}, false
		}
		parsed.sources = append(parsed.sources, operands...)
	case targetDirectorySeen:
		if len(operands) == 0 {
			return gnuMoveOperands{}, false
		}
		parsed.sources = append(parsed.sources, operands...)
	case noTargetDirectory:
		if len(operands) != 2 {
			return gnuMoveOperands{}, false
		}
		parsed.sources = append(parsed.sources, operands[0])
	default:
		if len(operands) < 2 {
			return gnuMoveOperands{}, false
		}
		parsed.sources = append(parsed.sources, operands[:len(operands)-1]...)
	}
	return parsed, true
}

func validGNUmoveBackupControl(value string) bool {
	if value == "" {
		return true
	}
	value = strings.ToLower(value)
	if stringIn(value, []string{"none", "off", "numbered", "t", "existing", "nil", "simple", "never"}) {
		return true
	}
	// GNU's enum binder permits unambiguous prefixes; a single "n" is
	// ambiguous across numbered, none, nil, and never.
	return strings.HasPrefix("numbered", value) && len(value) >= 2 ||
		strings.HasPrefix("existing", value) || strings.HasPrefix("simple", value) ||
		strings.HasPrefix("never", value) && len(value) >= 2 || strings.HasPrefix("nil", value) && len(value) >= 2 ||
		strings.HasPrefix("off", value)
}

func gnuMoveUpdateMode(value string) (string, bool) {
	value = strings.ToLower(value)
	for _, mode := range []string{"all", "none", "none-fail", "older"} {
		if value == mode {
			return mode, true
		}
	}
	if strings.HasPrefix("older", value) && value != "" {
		return "older", true
	}
	if strings.HasPrefix("all", value) && value != "" {
		return "all", true
	}
	// "n" is ambiguous between none and none-fail.
	if len(value) >= 2 && strings.HasPrefix("none", value) && !strings.HasPrefix("none-fail", value) {
		return "none", true
	}
	if strings.HasPrefix("none-fail", value) && len(value) > len("none") {
		return "none-fail", true
	}
	return "", false
}

func gnuMoveTargetDirectoryOption(value string) bool {
	return value == "--target-directory" ||
		strings.HasPrefix(value, "--target-d") && strings.HasPrefix("--target-directory", value)
}

func parseGNUmoveShortOptions(value string) (consumes string, backup bool, noClobber *bool, noTarget bool, update string, valid bool) {
	if len(value) < 2 || value[0] != '-' || strings.HasPrefix(value, "--") {
		return "", false, nil, false, "", false
	}
	valid = true
	for index := 1; index < len(value); index++ {
		switch value[index] {
		case 'f', 'i':
			state := false
			noClobber = &state
		case 'n':
			state := true
			noClobber = &state
		case 'b':
			backup = true
		case 'u':
			update = "older"
		case 'T':
			noTarget = true
		case 'v', 'Z':
			continue
		case 't':
			return "target-directory", backup, noClobber, noTarget, update, true
		case 'S':
			return "suffix", backup, noClobber, noTarget, update, true
		default:
			return "", false, nil, false, "", false
		}
	}
	return "", backup, noClobber, noTarget, update, true
}

func gnuMoveAttachedShortValue(value string, option byte) string {
	for index := 1; index < len(value); index++ {
		if value[index] != option {
			continue
		}
		return value[index+1:]
	}
	return ""
}

func (e *Evaluator) evaluateMoveTargetDirectory(args []literalArg, cwd string, cwdUncertain bool) scanResult {
	optionsDone := false
	result := scanResult{}
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
		protected, ambiguous := e.classifyCriticalRelocationTarget(arg.value, cwd, cwdUncertain)
		if ambiguous {
			result.addGap(gap("dynamic_path", "A relative move source depends on a prior current-directory change."))
			continue
		}
		if protected {
			return denied("WARD_DESTRUCTIVE_FILESYSTEM", destructiveFSReason)
		}
	}
	return result
}

func (e *Evaluator) catastrophicRM(args []literalArg, cwd string, cwdUncertain bool) bool {
	if !hasRecursiveRMFlag(args) {
		return false
	}
	optionsDone := false
	for _, arg := range args {
		if !arg.static {
			continue
		}
		if !optionsDone && arg.value == "--" {
			optionsDone = true
			continue
		}
		if !optionsDone && strings.HasPrefix(arg.value, "-") {
			continue
		}
		protected, ambiguous := e.classifyRecursiveDeleteTarget(arg.value, cwd, cwdUncertain)
		if !ambiguous && protected {
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
		if arg.value == "--" {
			break
		}
		if arg.value == "--recursive" || strings.HasPrefix(arg.value, "-") && !strings.HasPrefix(arg.value, "--") && strings.ContainsAny(arg.value[1:], "rR") {
			return true
		}
	}
	return false
}

func (e *Evaluator) candidateAtCWD(candidate, cwd string, cwdUncertain bool) (string, bool) {
	if e.boundaries.isAbsoluteCandidate(candidate) {
		return candidate, false
	}
	if cwdUncertain {
		return "", true
	}
	return path.Join(strings.ReplaceAll(cwd, `\`, "/"), candidate), false
}

func (e *Evaluator) classifyCriticalMutationTarget(candidate, cwd string, cwdUncertain bool) (protected, ambiguous bool) {
	resolved, ambiguous := e.candidateAtCWD(candidate, cwd, cwdUncertain)
	return !ambiguous && e.boundaries.protectsCriticalMetadata(resolved), ambiguous
}

func (e *Evaluator) classifyCriticalRelocationTarget(candidate, cwd string, cwdUncertain bool) (protected, ambiguous bool) {
	resolved, ambiguous := e.candidateAtCWD(candidate, cwd, cwdUncertain)
	return !ambiguous && e.boundaries.protectsCriticalRelocation(resolved), ambiguous
}

func (e *Evaluator) classifyRecursiveDeleteTarget(candidate, cwd string, cwdUncertain bool) (protected, ambiguous bool) {
	resolved, ambiguous := e.candidateAtCWD(candidate, cwd, cwdUncertain)
	return !ambiguous && e.boundaries.protectsRecursiveDelete(resolved), ambiguous
}

func destructiveGit(args []literalArg) bool {
	if len(args) == 0 || !args[0].static {
		return false
	}
	switch args[0].value {
	case "reset":
		return destructiveGitReset(args[1:])
	case "clean":
		return destructiveGitClean(args[1:])
	case "push":
		return destructiveGitPush(args[1:])
	default:
		return false
	}
}

func destructiveGitReset(args []literalArg) bool {
	mode := ""
	patchMode := false
	autoAdvanceSet := false
	autoAdvance := false
	diffContext := false
	pathspecFromFile := false
	pathspecFromFileEmpty := false
	pathspecFileNUL := false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !arg.static {
			return false
		}
		value := arg.value
		if value == "--" {
			break
		}
		if !strings.HasPrefix(value, "-") || value == "-" {
			continue
		}
		switch value {
		case "-h", "--help":
			return false
		case "--hard", "--soft", "--mixed", "--merge", "--keep":
			mode = value
		case "-p", "--patch":
			patchMode = true
		case "--no-patch":
			patchMode = false
		case "--auto-advance":
			autoAdvanceSet, autoAdvance = true, true
		case "--no-auto-advance":
			autoAdvanceSet, autoAdvance = true, false
		case "-q", "--quiet", "--no-quiet", "--no-refresh", "--refresh", "-N", "--intent-to-add",
			"--no-intent-to-add", "--recurse-submodules", "--no-recurse-submodules":
			continue
		case "--pathspec-file-nul":
			pathspecFileNUL = true
		case "--no-pathspec-file-nul":
			pathspecFileNUL = false
		case "--no-pathspec-from-file":
			pathspecFromFile, pathspecFromFileEmpty = false, false
		case "--pathspec-from-file":
			if index+1 >= len(args) || !args[index+1].static {
				return false
			}
			pathspecFromFile = true
			pathspecFromFileEmpty = args[index+1].value == ""
			index++
		case "-U", "--unified", "--inter-hunk-context":
			if index+1 >= len(args) || !args[index+1].static || !validGitContextLines(args[index+1].value) {
				return false
			}
			diffContext = true
			index++
		default:
			if strings.HasPrefix(value, "--pathspec-from-file=") {
				pathspecFromFile = true
				pathspecFromFileEmpty = strings.TrimPrefix(value, "--pathspec-from-file=") == ""
				continue
			}
			if strings.HasPrefix(value, "--recurse-submodules=") &&
				validGitBoolean(strings.TrimPrefix(value, "--recurse-submodules="), true) {
				continue
			}
			if strings.HasPrefix(value, "-U") && len(value) > len("-U") && validGitContextLines(strings.TrimPrefix(value, "-U")) {
				diffContext = true
				continue
			}
			if name, assigned, found := strings.Cut(value, "="); found &&
				(name == "--unified" || name == "--inter-hunk-context") && validGitContextLines(assigned) {
				diffContext = true
				continue
			}
			return false
		}
	}
	if patchMode && mode != "" || diffContext && !patchMode || autoAdvanceSet && !autoAdvance && !patchMode {
		return false
	}
	if pathspecFileNUL && (!pathspecFromFile || pathspecFromFileEmpty) {
		return false
	}
	return mode == "--hard" && !patchMode
}

func validGitBoolean(value string, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}
	switch strings.ToLower(value) {
	case "true", "false", "yes", "no", "on", "off", "1", "0":
		return true
	default:
		return false
	}
}

func validGitContextLines(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func destructiveGitClean(args []literalArg) bool {
	force, directories, dryRun := false, false, false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !arg.static {
			return false
		}
		value := arg.value
		if value == "--" {
			break
		}
		if !strings.HasPrefix(value, "-") || value == "-" {
			continue
		}
		switch value {
		case "-h", "--help":
			return false
		case "--force":
			force = true
		case "--no-force":
			force = false
		case "--dry-run":
			dryRun = true
		case "--no-dry-run":
			dryRun = false
		case "--interactive", "--no-interactive", "--quiet", "--no-quiet":
			continue
		case "--exclude", "-e":
			if index+1 >= len(args) || !args[index+1].static {
				return false
			}
			index++
		default:
			if strings.HasPrefix(value, "--exclude=") {
				continue
			}
			if strings.HasPrefix(value, "--") || !parseGitCleanShortOptions(value, &force, &directories, &dryRun) {
				return false
			}
			if strings.Contains(value[1:], "e") && strings.HasSuffix(value, "e") {
				if index+1 >= len(args) || !args[index+1].static {
					return false
				}
				index++
			}
		}
	}
	return force && directories && !dryRun
}

func parseGitCleanShortOptions(value string, force, directories, dryRun *bool) bool {
	if len(value) < 2 || value[0] != '-' || strings.HasPrefix(value, "--") {
		return false
	}
	for index := 1; index < len(value); index++ {
		switch value[index] {
		case 'f':
			*force = true
		case 'd':
			*directories = true
		case 'n':
			*dryRun = true
		case 'i', 'q', 'x', 'X':
			continue
		case 'e':
			// -e consumes the remainder of this token, or the next token when
			// it is the final short option.
			return true
		default:
			return false
		}
	}
	return true
}

func destructiveGitPush(args []literalArg) bool {
	force, mirror, dryRun, repositorySeen, forcedRefspec := false, false, false, false, false
	terminated := false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !arg.static {
			return false
		}
		value := arg.value
		if !terminated && value == "--" {
			terminated = true
			continue
		}
		if !terminated && strings.HasPrefix(value, "-") && value != "-" {
			switch value {
			case "-h", "--help":
				return false
			case "-f", "--force":
				force = true
			case "--no-force":
				force = false
			case "--mirror":
				mirror = true
			case "--no-mirror":
				mirror = false
			case "-n", "--dry-run":
				dryRun = true
			case "--no-dry-run":
				dryRun = false
			case "--repo", "--receive-pack", "--exec", "--push-option", "-o":
				if index+1 >= len(args) || !args[index+1].static || args[index+1].value == "" {
					return false
				}
				if value == "--repo" {
					repositorySeen = true
				}
				index++
			case "--recurse-submodules":
				if index+1 >= len(args) || !args[index+1].static || !validGitPushRecurseSubmodules(args[index+1].value) {
					return false
				}
				index++
			case "--no-repo":
				repositorySeen = false
			case "--all", "--no-all", "--branches", "--no-branches", "--tags", "--no-tags",
				"--follow-tags", "--no-follow-tags", "--atomic", "--no-atomic", "--delete", "--no-delete", "-d",
				"--prune", "--no-prune", "--porcelain", "--no-porcelain", "--quiet", "--no-quiet", "-q",
				"--verbose", "--no-verbose", "-v", "--set-upstream", "--no-set-upstream", "-u",
				"--no-verify", "--ipv4", "-4", "--ipv6", "-6", "--force-if-includes",
				"--no-force-if-includes", "--force-with-lease", "--no-force-with-lease", "--progress", "--no-progress",
				"--signed", "--no-signed", "--thin", "--no-thin", "--verify",
				"--no-receive-pack", "--no-exec", "--no-push-option", "--no-recurse-submodules":
				continue
			default:
				name, assigned, hasAssignment := strings.Cut(value, "=")
				switch name {
				case "--repo", "--receive-pack", "--exec", "--push-option":
					if !hasAssignment || assigned == "" {
						return false
					}
					if name == "--repo" {
						repositorySeen = true
					}
					continue
				case "--force-with-lease", "--signed", "--recurse-submodules":
					if hasAssignment && assigned != "" &&
						(name != "--signed" || validGitPushSigned(assigned)) &&
						(name != "--recurse-submodules" || validGitPushRecurseSubmodules(assigned)) {
						continue
					}
				}
				if strings.HasPrefix(value, "-o") && len(value) > 2 {
					continue
				}
				validShort, consumesNext := parseGitPushShortOptions(value, &force, &dryRun)
				if validShort {
					if consumesNext {
						if index+1 >= len(args) || !args[index+1].static || args[index+1].value == "" {
							return false
						}
						index++
					}
					continue
				}
				return false
			}
			continue
		}
		if !repositorySeen {
			repositorySeen = true
			continue
		}
		if len(value) > 1 && strings.HasPrefix(value, "+") {
			forcedRefspec = true
		}
	}
	return !dryRun && (force || mirror || forcedRefspec)
}

func parseGitPushShortOptions(value string, force, dryRun *bool) (bool, bool) {
	if len(value) < 2 || value[0] != '-' || strings.HasPrefix(value, "--") {
		return false, false
	}
	for index := 1; index < len(value); index++ {
		switch value[index] {
		case 'f':
			*force = true
		case 'n':
			*dryRun = true
		case 'v', 'q', 'u', 'd', '4', '6':
			continue
		case 'o':
			return true, index+1 == len(value)
		default:
			return false, false
		}
	}
	return true, false
}

func validGitPushSigned(value string) bool {
	return validGitBoolean(value, false) || value == "if-asked"
}

func validGitPushRecurseSubmodules(value string) bool {
	return stringIn(value, []string{"check", "on-demand", "no", "only"})
}

func destructiveTerraform(args []literalArg) bool {
	if len(args) == 0 || !args[0].static {
		return false
	}
	if args[0].value == "destroy" {
		return !terraformDestroyInformational(args[1:])
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

func terraformDestroyInformational(args []literalArg) bool {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !arg.static {
			return false
		}
		if arg.value == "--" {
			return false
		}
		if terraformApplyValueOption(arg.value) {
			if index+1 >= len(args) || !args[index+1].static {
				return false
			}
			index++
			continue
		}
		if arg.value == "-help" || arg.value == "--help" || arg.value == "-h" {
			return true
		}
	}
	return false
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
		case value == "--compatibility" || value == "--all-resources":
			current = current[1:]
		case strings.HasPrefix(value, "--compatibility=") || strings.HasPrefix(value, "--all-resources="):
			_, assigned, _ := strings.Cut(value, "=")
			if _, valid := composeBooleanValue(assigned); !valid {
				return false, gap("unsupported_compose_option", "A Docker Compose boolean option is outside Ward classification.")
			}
			current = current[1:]
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
		"--ansi", "--parallel", "--progress":
		return true
	default:
		return false
	}
}

func composeAssignedValueOption(value string) bool {
	for _, name := range []string{"--file", "--env-file", "--profile", "--project-directory", "--project-name", "--ansi", "--parallel", "--progress"} {
		if strings.HasPrefix(value, name+"=") {
			return validComposeGlobalValue(name, strings.TrimPrefix(value, name+"="))
		}
	}
	return false
}

func validComposeGlobalValue(name, value string) bool {
	switch name {
	case "--ansi":
		return value == "" || stringIn(strings.ToLower(value), []string{"auto", "always", "never"})
	case "--progress":
		return value == "" || stringIn(value, []string{"auto", "tty", "plain", "json", "quiet"})
	case "--parallel":
		return validComposeInteger(value)
	case "-f", "--file", "--env-file", "--profile", "--project-directory", "-p", "--project-name":
		return true
	default:
		return false
	}
}

func composeAttachedShortValueOption(value string) bool {
	return strings.HasPrefix(value, "-f") && len(value) > 2 || strings.HasPrefix(value, "-p") && len(value) > 2
}

func destructiveComposeDown(args []literalArg, dryRun bool) (bool, *contract.CoverageGap) {
	volumes := false
	optionsDone := false
	for index := 0; index < len(args); index++ {
		if !args[index].static {
			return false, gap("dynamic_compose_option", "A Docker Compose down option contains runtime expansion.")
		}
		value := args[index].value
		if !optionsDone && value == "--" {
			optionsDone = true
			continue
		}
		if optionsDone {
			if !validComposeServiceName(value, true) {
				return false, gap("unsupported_compose_option", "A Docker Compose service name is outside Ward classification.")
			}
			continue
		}
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
			if found && (name == "--volumes" || name == "-v") {
				parsed, valid := composeBooleanValue(assigned)
				if !valid {
					return false, gap("unsupported_compose_option", "A Docker Compose volumes value is outside Ward classification.")
				}
				volumes = parsed
				continue
			}
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
			if found && name == "--remove-orphans" {
				if _, valid := composeBooleanValue(assigned); !valid {
					return false, gap("unsupported_compose_option", "A Docker Compose remove-orphans value is outside Ward classification.")
				}
				continue
			}
			if strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "--") {
				parsedVolumes, consumesNext, valid := parseComposeDownShortOptions(value, volumes)
				if valid {
					volumes = parsedVolumes
					if consumesNext {
						if index+1 >= len(args) || !args[index+1].static || !validComposeDownValue("-t", args[index+1].value) {
							return false, gap("unsupported_compose_option", "A Docker Compose timeout is missing a valid literal argument.")
						}
						index++
					}
					continue
				}
			}
			if validComposeServiceName(value, false) {
				continue
			}
			return false, gap("unsupported_compose_option", "A Docker Compose down option is outside Ward classification.")
		}
	}
	return volumes && !dryRun, nil
}

func composeDryRunValue(value string) (bool, bool) {
	return composeBooleanValue(value)
}

func composeBooleanValue(value string) (bool, bool) {
	parsed, err := strconv.ParseBool(value)
	return parsed, err == nil
}

func validComposeServiceName(value string, optionsDone bool) bool {
	if value == "" {
		return false
	}
	first := rune(value[0])
	if !asciiAlphaNumeric(first) && first != '_' && first != '.' && !(optionsDone && first == '-') {
		return false
	}
	if len(value) == 1 && !asciiAlphaNumeric(first) {
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
	return validComposeInteger(value)
}

func validComposeInteger(value string) bool {
	if !signedDecimal(value) {
		return false
	}
	_, err := strconv.ParseInt(value, 10, 64)
	return err == nil
}

func parseComposeDownShortOptions(value string, volumes bool) (bool, bool, bool) {
	if len(value) < 2 || value[0] != '-' || strings.HasPrefix(value, "--") {
		return volumes, false, false
	}
	for index := 1; index < len(value); index++ {
		switch value[index] {
		case 'v':
			if index+1 < len(value) && value[index+1] == '=' {
				parsed, valid := composeBooleanValue(value[index+2:])
				return parsed, false, valid
			}
			volumes = true
		case 't':
			attached := strings.TrimPrefix(value[index+1:], "=")
			if attached == "" {
				return volumes, true, true
			}
			return volumes, false, validComposeDownValue("-t", attached)
		default:
			return volumes, false, false
		}
	}
	return volumes, false, true
}

func destructiveKubectl(args []literalArg) (bool, *contract.CoverageGap) {
	if len(args) < 2 || !literalAt(args, 0, "delete") {
		return false, nil
	}
	optionsDone := false
	dryRun := false
	resourceMode := ""
	destructiveResource := false
	for index := 1; index < len(args); index++ {
		arg := args[index]
		if !arg.static {
			return false, gap("dynamic_kubectl_delete_option", "A kubectl delete argument contains runtime expansion.")
		}
		if !optionsDone && arg.value == "--" {
			optionsDone = true
			continue
		}
		if !optionsDone && strings.HasPrefix(arg.value, "-") && arg.value != "-" {
			if arg.value == "--dry-run" {
				dryRun = true
				continue
			}
			if strings.HasPrefix(arg.value, "--dry-run=") {
				parsed, valid := kubectlDryRunValue(strings.TrimPrefix(arg.value, "--dry-run="))
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
		if resourceMode == "" {
			if strings.Contains(arg.value, "/") {
				resourceMode = "tuple"
				typeName, valid := kubectlResourceTuple(arg.value)
				if !valid {
					return false, gap("unsupported_kubectl_resource_type", "A kubectl resource tuple is outside Ward classification.")
				}
				destructiveResource = destructiveResource || kubectlNamespaceResource(typeName)
				continue
			}
			resourceMode = "type"
			resourceTypes, valid := kubectlResourceTypeList(arg.value)
			if !valid {
				return false, gap("unsupported_kubectl_resource_type", "A kubectl resource type is outside Ward classification.")
			}
			for _, resourceType := range resourceTypes {
				destructiveResource = destructiveResource || kubectlNamespaceResource(resourceType)
			}
			continue
		}
		if resourceMode == "tuple" {
			typeName, valid := kubectlResourceTuple(arg.value)
			if !valid {
				return false, gap("unsupported_kubectl_resource_type", "A kubectl resource tuple is outside Ward classification.")
			}
			destructiveResource = destructiveResource || kubectlNamespaceResource(typeName)
			continue
		}
		if strings.Contains(arg.value, "/") {
			return false, gap("unsupported_kubectl_resource_type", "Mixed kubectl resource type and tuple forms are outside Ward classification.")
		}
	}
	if dryRun {
		return false, nil
	}
	return destructiveResource, nil
}

func kubectlDryRunValue(value string) (bool, bool) {
	switch value {
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
	if kubectlAttachedGlobalOption(value) {
		return index + 1, true
	}
	if stringIn(value, []string{"--all", "--all-namespaces", "-A", "--force", "--ignore-not-found", "--interactive", "-i", "--now", "--recursive", "-R", "--wait"}) {
		return index + 1, true
	}
	if name, assigned, found := strings.Cut(value, "="); found &&
		stringIn(name, []string{"--all", "--all-namespaces", "-A", "--force", "--ignore-not-found", "--interactive", "-i", "--now", "--recursive", "-R", "--wait"}) {
		_, err := strconv.ParseBool(assigned)
		return index + 1, err == nil
	}
	if value == "--cascade" {
		return index + 1, true
	}
	if strings.HasPrefix(value, "--cascade=") {
		return index + 1, stringIn(strings.TrimPrefix(value, "--cascade="), []string{"background", "foreground", "orphan"})
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
	if strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "--") {
		return index + 1, reviewedKubectlDeleteShortCluster(value)
	}
	return index, false
}

func reviewedKubectlDeleteShortCluster(value string) bool {
	if len(value) < 2 || value[0] != '-' || value[1] == '-' {
		return false
	}
	for index := 1; index < len(value); index++ {
		switch value[index] {
		case 'A', 'i', 'R':
			if index+1 < len(value) && value[index+1] == '=' {
				_, err := strconv.ParseBool(value[index+2:])
				return err == nil
			}
		case 'v':
			assigned := strings.TrimPrefix(value[index+1:], "=")
			return validKubectlGlobalOptionValue("-v", assigned)
		case 'n', 's':
			assigned := strings.TrimPrefix(value[index+1:], "=")
			return assigned != ""
		default:
			return false
		}
	}
	return true
}

func kubectlResourceTypeList(value string) ([]string, bool) {
	parts := strings.Split(strings.ToLower(value), ",")
	if len(parts) == 0 {
		return nil, false
	}
	for _, part := range parts {
		if !validKubectlResourceType(part) {
			return nil, false
		}
	}
	return parts, true
}

func kubectlResourceTuple(value string) (string, bool) {
	typeName, resourceName, found := strings.Cut(strings.ToLower(value), "/")
	if !found || !validKubectlResourceType(typeName) || resourceName == "" || strings.Contains(resourceName, "/") || strings.ContainsAny(resourceName, " \t\r\n,") {
		return "", false
	}
	return typeName, true
}

func validKubectlResourceType(value string) bool {
	if value == "" || !asciiAlphaNumeric(rune(value[0])) {
		return false
	}
	for _, char := range value[1:] {
		if !asciiAlphaNumeric(char) && char != '-' && char != '.' {
			return false
		}
	}
	return true
}

func kubectlNamespaceResource(value string) bool {
	switch strings.ToLower(value) {
	case "namespace", "namespaces", "ns":
		return true
	default:
		return false
	}
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
