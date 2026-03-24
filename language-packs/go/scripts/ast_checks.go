// Go AST Anti-Pattern Checker
//
// Detects Go-specific anti-patterns using go/ast:
//   - Unchecked errors (the #1 Go bug)
//   - Bare goroutines (no recovery, no sync)
//   - Deep nesting (>5 levels of control flow)
//   - God struct (>15 methods on a receiver)
//   - Magic numbers (unexplained numeric literals)
//   - Empty interface abuse (excessive interface{}/any params)
//   - Context not first param (violates Go convention)
//   - Large interface (>5 methods, Go prefers small interfaces)
//   - init() with side effects
//
// Uses only Go stdlib -- zero external dependencies, zero license concerns.

package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const packVersion = "go_v1"

// Finding matches the @refract/core Finding schema exactly.
type Finding struct {
	ID              string   `json:"id"`
	Antipattern     string   `json:"antipattern"`
	AntipatternName string   `json:"antipattern_name"`
	Category        string   `json:"category"`
	Severity        string   `json:"severity"`
	Confidence      float64  `json:"confidence"`
	File            string   `json:"file"`
	LineStart       int      `json:"line_start"`
	LineEnd         int      `json:"line_end"`
	Language        string   `json:"language"`
	LanguagePack    string   `json:"language_pack"`
	Message         string   `json:"message"`
	Remediation     string   `json:"remediation"`
	Effort          string   `json:"effort"`
	Tool            string   `json:"tool"`
	RuleID          string   `json:"rule_id"`
	CodeSnippet     string   `json:"code_snippet,omitempty"`
	References      []string `json:"references,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	DetectedAt      string   `json:"detected_at"`
}

type Result struct {
	Findings []Finding `json:"findings"`
	Count    int       `json:"count"`
}

func makeID() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 9)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// -- Skip directories --

var skipDirs = map[string]bool{
	"vendor": true, ".git": true, "node_modules": true, "dist": true,
	"build": true, "testdata": true, ".cache": true,
}

// -- Checker context --

type checker struct {
	fset     *token.FileSet
	file     string // relative path
	findings []Finding
	source   []byte
}

func (c *checker) add(f Finding) {
	f.DetectedAt = now()
	f.Language = "go"
	f.LanguagePack = packVersion
	f.File = c.file
	f.Tool = "ast-checker"
	f.ID = makeID()
	c.findings = append(c.findings, f)
}

func (c *checker) snippet(pos, end token.Pos) string {
	start := c.fset.Position(pos).Offset
	finish := c.fset.Position(end).Offset
	if start < 0 || finish < 0 || start >= len(c.source) {
		return ""
	}
	if finish > len(c.source) {
		finish = len(c.source)
	}
	s := string(c.source[start:finish])
	if len(s) > 500 {
		s = s[:500] + "..."
	}
	return s
}

// ============================================================================
// CHECK: Unchecked errors
// ============================================================================

func (c *checker) checkUncheckedErrors(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		// Look for _ = someFunc() where the function returns error
		for _, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok || ident.Name != "_" {
				continue
			}
			// Check if RHS is a function call (heuristic: any blank identifier
			// on the result of a call is suspicious)
			for _, rhs := range assign.Rhs {
				call, ok := rhs.(*ast.CallExpr)
				if !ok {
					continue
				}
				pos := c.fset.Position(assign.Pos())
				funcName := exprName(call.Fun)
				c.add(Finding{
					Antipattern:     "error_not_checked",
					AntipatternName: "Unchecked Error",
					Category:        "code_structure",
					Severity:        "high",
					Confidence:      0.85,
					LineStart:       pos.Line,
					LineEnd:         pos.Line,
					Message:         fmt.Sprintf("Return value of %s() assigned to blank identifier '_'. If this returns an error, it will be silently ignored.", funcName),
					Remediation:     fmt.Sprintf("Handle the error: `if err := %s(...); err != nil { return err }`", funcName),
					Effort:          "minutes",
					RuleID:          "go/unchecked-error",
					References:      []string{"https://go.dev/doc/effective_go#errors"},
					Tags:            []string{"errors", "reliability"},
				})
			}
		}
		return true
	})
}

// ============================================================================
// CHECK: Bare goroutines
// ============================================================================

func (c *checker) checkBareGoroutines(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		goStmt, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}

		// Check if the goroutine body has a recover() call
		hasRecover := false
		ast.Inspect(goStmt.Call, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "recover" {
				hasRecover = true
				return false
			}
			return true
		})

		if !hasRecover {
			pos := c.fset.Position(goStmt.Pos())
			c.add(Finding{
				Antipattern:     "bare_goroutine",
				AntipatternName: "Bare Goroutine",
				Category:        "concurrency",
				Severity:        "medium",
				Confidence:      0.8,
				LineStart:       pos.Line,
				LineEnd:         pos.Line,
				Message:         "Goroutine launched without recover(). A panic in this goroutine will crash the entire program.",
				Remediation:     "Add a deferred recover() at the top of the goroutine: `go func() { defer func() { if r := recover(); r != nil { log.Printf(\"recovered: %v\", r) } }(); ... }()`",
				Effort:          "minutes",
				RuleID:          "go/bare-goroutine",
				References:      []string{"https://go.dev/doc/effective_go#recover"},
				Tags:            []string{"concurrency", "reliability"},
			})
		}
		return true
	})
}

// ============================================================================
// CHECK: Deep nesting
// ============================================================================

func (c *checker) checkDeepNesting(file *ast.File) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Body != nil {
			maxDepth := nestingDepth(fn.Body, 0)
			if maxDepth >= 5 {
				pos := c.fset.Position(fn.Pos())
				endPos := c.fset.Position(fn.End())
				sev := "medium"
				if maxDepth >= 7 {
					sev = "high"
				}
				c.add(Finding{
					Antipattern:     "deep_nesting",
					AntipatternName: "Deep Nesting",
					Category:        "code_structure",
					Severity:        sev,
					Confidence:      0.85,
					LineStart:       pos.Line,
					LineEnd:         endPos.Line,
					Message:         fmt.Sprintf("Function '%s' has nesting depth of %d (threshold: 5).", fn.Name.Name, maxDepth),
					Remediation:     "Reduce nesting with early returns, extracted helper functions, or table-driven logic.",
					Effort:          "hours",
					RuleID:          "go/deep-nesting",
					Tags:            []string{"maintainability", "readability"},
				})
			}
		}
	}
}

func nestingDepth(block *ast.BlockStmt, depth int) int {
	if block == nil {
		return depth
	}
	maxD := depth
	for _, stmt := range block.List {
		d := stmtNestingDepth(stmt, depth)
		if d > maxD {
			maxD = d
		}
	}
	return maxD
}

func stmtNestingDepth(stmt ast.Stmt, depth int) int {
	maxD := depth
	switch s := stmt.(type) {
	case *ast.IfStmt:
		d := nestingDepth(s.Body, depth+1)
		if d > maxD {
			maxD = d
		}
		// else/else-if at same depth (sibling, not child)
		if s.Else != nil {
			if elseBlock, ok := s.Else.(*ast.BlockStmt); ok {
				d = nestingDepth(elseBlock, depth)
				if d > maxD {
					maxD = d
				}
			} else {
				d = stmtNestingDepth(s.Else, depth)
				if d > maxD {
					maxD = d
				}
			}
		}
	case *ast.ForStmt:
		d := nestingDepth(s.Body, depth+1)
		if d > maxD {
			maxD = d
		}
	case *ast.RangeStmt:
		d := nestingDepth(s.Body, depth+1)
		if d > maxD {
			maxD = d
		}
	case *ast.SwitchStmt:
		d := nestingDepth(s.Body, depth+1)
		if d > maxD {
			maxD = d
		}
	case *ast.TypeSwitchStmt:
		d := nestingDepth(s.Body, depth+1)
		if d > maxD {
			maxD = d
		}
	case *ast.SelectStmt:
		d := nestingDepth(s.Body, depth+1)
		if d > maxD {
			maxD = d
		}
	case *ast.BlockStmt:
		d := nestingDepth(s, depth)
		if d > maxD {
			maxD = d
		}
	case *ast.CaseClause:
		for _, bodyStmt := range s.Body {
			d := stmtNestingDepth(bodyStmt, depth)
			if d > maxD {
				maxD = d
			}
		}
	case *ast.CommClause:
		for _, bodyStmt := range s.Body {
			d := stmtNestingDepth(bodyStmt, depth)
			if d > maxD {
				maxD = d
			}
		}
	// try (not in Go) / with -- skip depth increment
	}
	return maxD
}

// ============================================================================
// CHECK: God struct (too many methods)
// ============================================================================

func (c *checker) checkGodStruct(file *ast.File) {
	methods := map[string][]token.Pos{} // receiver type -> positions

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
			continue
		}
		recvType := receiverTypeName(fn.Recv.List[0].Type)
		if recvType != "" {
			methods[recvType] = append(methods[recvType], fn.Pos())
		}
	}

	for typeName, positions := range methods {
		if len(positions) > 15 {
			pos := c.fset.Position(positions[0])
			sev := "medium"
			if len(positions) > 30 {
				sev = "high"
			}
			c.add(Finding{
				Antipattern:     "god_class",
				AntipatternName: "God Struct",
				Category:        "code_structure",
				Severity:        sev,
				Confidence:      0.85,
				LineStart:       pos.Line,
				LineEnd:         pos.Line,
				Message:         fmt.Sprintf("Type '%s' has %d methods. Large types are hard to understand and test.", typeName, len(positions)),
				Remediation:     fmt.Sprintf("Decompose '%s' into smaller types grouped by responsibility.", typeName),
				Effort:          "days",
				RuleID:          "go/god-struct",
				References:      []string{"https://refactoring.guru/smells/large-class"},
				Tags:            []string{"maintainability", "srp"},
			})
		}
	}
}

// ============================================================================
// CHECK: Magic numbers
// ============================================================================

// Only truly trivial values are unconditionally allowed.
// Everything else is filtered by context, not by value.
var trivialNumbers = map[string]bool{
	"0": true, "1": true, "-1": true,
}

func (c *checker) checkMagicNumbers(file *ast.File) {
	// Collect positions to skip: const blocks and var declarations with names
	skipPositions := map[token.Pos]bool{}

	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		// Skip const blocks entirely
		if genDecl.Tok == token.CONST {
			ast.Inspect(genDecl, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok {
					skipPositions[lit.Pos()] = true
				}
				return true
			})
		}
		// Skip named var declarations: var bufSize = 4096
		if genDecl.Tok == token.VAR {
			for _, spec := range genDecl.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) == 0 {
					continue
				}
				// Only skip if the var has a meaningful name (not _ or single letter)
				name := vs.Names[0].Name
				if len(name) > 1 && name != "_" {
					ast.Inspect(vs, func(n ast.Node) bool {
						if lit, ok := n.(*ast.BasicLit); ok {
							skipPositions[lit.Pos()] = true
						}
						return true
					})
				}
			}
		}
	}

	// Build a map of literal positions -> their parent context for contextual filtering
	type literalContext struct {
		inComparison   bool // if x == 200 { (HTTP status check)
		inBitOp        bool // x & 0x80 (bitmask)
		inSliceExpr    bool // s[0:4] (slice bounds)
		inMapLiteral   bool // map[string]int{"a": 1}
		inTestFile     bool
	}

	isTestFile := strings.HasSuffix(c.file, "_test.go")

	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || (lit.Kind != token.INT && lit.Kind != token.FLOAT) {
			return true
		}
		if trivialNumbers[lit.Value] {
			return true
		}
		if skipPositions[lit.Pos()] {
			return true
		}
		// Skip test files -- tests legitimately use literal values in assertions
		if isTestFile {
			return true
		}
		// Skip hex literals used in bitwise context (bitmasks are self-documenting)
		if strings.HasPrefix(lit.Value, "0x") || strings.HasPrefix(lit.Value, "0X") {
			return true
		}
		// Skip file permission modes (e.g., 0644, 0755)
		if strings.HasPrefix(lit.Value, "0") && len(lit.Value) >= 3 && lit.Kind == token.INT {
			return true
		}

		pos := c.fset.Position(lit.Pos())
		c.add(Finding{
			Antipattern:     "magic_number",
			AntipatternName: "Magic Number",
			Category:        "code_structure",
			Severity:        "low",
			Confidence:      0.7,
			LineStart:       pos.Line,
			LineEnd:         pos.Line,
			Message:         fmt.Sprintf("Magic number `%s` -- unexplained numeric literal.", lit.Value),
			Remediation:     fmt.Sprintf("Extract to a named constant: `const threshold = %s`", lit.Value),
			Effort:          "minutes",
			RuleID:          "go/magic-number",
			Tags:            []string{"readability", "maintainability"},
		})
		return true
	})
}

// ============================================================================
// CHECK: Empty interface abuse (interface{} / any params)
// ============================================================================

func (c *checker) checkEmptyInterfaceAbuse(file *ast.File) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Type.Params == nil {
			continue
		}

		anyCount := 0
		for _, field := range fn.Type.Params.List {
			if isEmptyInterface(field.Type) {
				anyCount += len(field.Names)
				if len(field.Names) == 0 {
					anyCount++
				}
			}
		}

		if anyCount >= 3 {
			pos := c.fset.Position(fn.Pos())
			c.add(Finding{
				Antipattern:     "empty_interface_abuse",
				AntipatternName: "Empty Interface Abuse",
				Category:        "code_structure",
				Severity:        "medium",
				Confidence:      0.8,
				LineStart:       pos.Line,
				LineEnd:         pos.Line,
				Message:         fmt.Sprintf("Function '%s' has %d interface{}/any parameters. This defeats Go's type system.", fn.Name.Name, anyCount),
				Remediation:     "Use specific types, type constraints (generics), or define a minimal interface.",
				Effort:          "hours",
				RuleID:          "go/empty-interface-abuse",
				References:      []string{"https://go.dev/doc/effective_go#interface_methods"},
				Tags:            []string{"type-safety", "maintainability"},
			})
		}
	}
}

// ============================================================================
// CHECK: context.Context not first param
// ============================================================================

func (c *checker) checkContextFirstParam(file *ast.File) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Type.Params == nil || len(fn.Type.Params.List) < 2 {
			continue
		}

		// Check if any param is context.Context but NOT the first one
		fields := fn.Type.Params.List
		firstIsCtx := isContextType(fields[0].Type)
		hasCtxLater := false

		for i := 1; i < len(fields); i++ {
			if isContextType(fields[i].Type) {
				hasCtxLater = true
				break
			}
		}

		if hasCtxLater && !firstIsCtx {
			pos := c.fset.Position(fn.Pos())
			c.add(Finding{
				Antipattern:     "context_not_first_param",
				AntipatternName: "Context Not First Parameter",
				Category:        "code_structure",
				Severity:        "medium",
				Confidence:      0.95,
				LineStart:       pos.Line,
				LineEnd:         pos.Line,
				Message:         fmt.Sprintf("Function '%s' has context.Context but not as the first parameter. Go convention requires ctx as the first arg.", fn.Name.Name),
				Remediation:     fmt.Sprintf("Move context.Context to be the first parameter: `func %s(ctx context.Context, ...)`", fn.Name.Name),
				Effort:          "minutes",
				RuleID:          "go/context-not-first",
				References:      []string{"https://go.dev/blog/context#package-context"},
				Tags:            []string{"convention", "stdlib"},
			})
		}
	}
}

// ============================================================================
// CHECK: Large interface (>5 methods)
// ============================================================================

func (c *checker) checkLargeInterface(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		iface, ok := typeSpec.Type.(*ast.InterfaceType)
		if !ok || iface.Methods == nil {
			return true
		}

		methodCount := len(iface.Methods.List)
		if methodCount > 5 {
			pos := c.fset.Position(typeSpec.Pos())
			sev := "medium"
			if methodCount > 10 {
				sev = "high"
			}
			c.add(Finding{
				Antipattern:     "large_interface",
				AntipatternName: "Large Interface",
				Category:        "code_structure",
				Severity:        sev,
				Confidence:      0.85,
				LineStart:       pos.Line,
				LineEnd:         pos.Line,
				Message:         fmt.Sprintf("Interface '%s' has %d methods. Go prefers small, focused interfaces.", typeSpec.Name.Name, methodCount),
				Remediation:     fmt.Sprintf("Split '%s' into smaller interfaces with 1-3 methods each. Consumers should define the interfaces they need.", typeSpec.Name.Name),
				Effort:          "hours",
				RuleID:          "go/large-interface",
				References:      []string{"https://go.dev/doc/effective_go#interfaces"},
				Tags:            []string{"design", "go-idiom"},
			})
		}
		return true
	})
}

// ============================================================================
// CHECK: init() with side effects
// ============================================================================

func (c *checker) checkInitSideEffects(file *ast.File) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "init" || fn.Body == nil {
			continue
		}

		// Count statements -- complex init() functions are suspicious
		stmtCount := countStatements(fn.Body)
		if stmtCount > 5 {
			pos := c.fset.Position(fn.Pos())
			c.add(Finding{
				Antipattern:     "init_side_effects",
				AntipatternName: "Complex init() Function",
				Category:        "code_structure",
				Severity:        "medium",
				Confidence:      0.75,
				LineStart:       pos.Line,
				LineEnd:         c.fset.Position(fn.End()).Line,
				Message:         fmt.Sprintf("init() has %d statements. Complex init functions make testing difficult and hide side effects.", stmtCount),
				Remediation:     "Move initialization logic to explicit Setup() or New() functions that can be called and tested directly.",
				Effort:          "hours",
				RuleID:          "go/init-side-effects",
				Tags:            []string{"testability", "maintainability"},
			})
		}
	}
}

// ============================================================================
// CHECK: defer in loop
// ============================================================================

func (c *checker) checkDeferInLoop(file *ast.File) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			// Look for for/range loops
			var loopBody *ast.BlockStmt
			switch stmt := n.(type) {
			case *ast.ForStmt:
				loopBody = stmt.Body
			case *ast.RangeStmt:
				loopBody = stmt.Body
			default:
				return true
			}
			// Check if defer appears in the loop body
			ast.Inspect(loopBody, func(inner ast.Node) bool {
				deferStmt, ok := inner.(*ast.DeferStmt)
				if !ok {
					return true
				}
				pos := c.fset.Position(deferStmt.Pos())
				funcName := exprName(deferStmt.Call.Fun)
				c.add(Finding{
					Antipattern:     "defer_in_loop",
					AntipatternName: "Defer in Loop",
					Category:        "code_structure",
					Severity:        "high",
					Confidence:      0.95,
					LineStart:       pos.Line,
					LineEnd:         pos.Line,
					Message:         fmt.Sprintf("defer %s() inside a loop. Deferred calls only execute when the function returns, not at the end of each iteration. This causes resource leaks.", funcName),
					Remediation:     "Move the deferred call into a helper function called per iteration, or close the resource explicitly at the end of each loop body.",
					Effort:          "minutes",
					RuleID:          "go/defer-in-loop",
					References:      []string{"https://go.dev/doc/effective_go#defer"},
					Tags:            []string{"resource-leak", "reliability"},
				})
				return false // don't descend further into this defer
			})
			return true
		})
	}
}

// ============================================================================
// CHECK: errors.New(fmt.Sprintf(...)) instead of fmt.Errorf
// ============================================================================

func (c *checker) checkErrorStringFormat(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		// errors.New(fmt.Sprintf(...))
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "New" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "errors" {
			return true
		}
		if len(call.Args) != 1 {
			return true
		}
		innerCall, ok := call.Args[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		innerSel, ok := innerCall.Fun.(*ast.SelectorExpr)
		if !ok || innerSel.Sel.Name != "Sprintf" {
			return true
		}
		innerPkg, ok := innerSel.X.(*ast.Ident)
		if !ok || innerPkg.Name != "fmt" {
			return true
		}

		pos := c.fset.Position(call.Pos())
		c.add(Finding{
			Antipattern:     "error_string_format",
			AntipatternName: "Verbose Error Construction",
			Category:        "code_structure",
			Severity:        "low",
			Confidence:      1.0,
			LineStart:       pos.Line,
			LineEnd:         pos.Line,
			Message:         "errors.New(fmt.Sprintf(...)) should be fmt.Errorf(...). Simpler and supports %w for error wrapping.",
			Remediation:     "Replace with fmt.Errorf() which combines formatting and error creation. Use %w to wrap underlying errors.",
			Effort:          "minutes",
			RuleID:          "go/error-string-format",
			Tags:            []string{"go-idiom", "readability"},
		})
		return true
	})
}

// ============================================================================
// CHECK: Loop variable captured by goroutine closure
// ============================================================================

func (c *checker) checkGoroutineClosureCapture(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		var loopVar string
		var loopBody *ast.BlockStmt

		switch stmt := n.(type) {
		case *ast.RangeStmt:
			if ident, ok := stmt.Key.(*ast.Ident); ok && ident.Name != "_" {
				loopVar = ident.Name
			}
			if loopVar == "" {
				if ident, ok := stmt.Value.(*ast.Ident); ok && ident.Name != "_" {
					loopVar = ident.Name
				}
			}
			loopBody = stmt.Body
		case *ast.ForStmt:
			// for i := 0; ... pattern
			if assign, ok := stmt.Init.(*ast.AssignStmt); ok && len(assign.Lhs) > 0 {
				if ident, ok := assign.Lhs[0].(*ast.Ident); ok {
					loopVar = ident.Name
				}
			}
			loopBody = stmt.Body
		default:
			return true
		}

		if loopVar == "" || loopBody == nil {
			return true
		}

		// Look for go func() { ... loopVar ... }() inside the loop
		ast.Inspect(loopBody, func(inner ast.Node) bool {
			goStmt, ok := inner.(*ast.GoStmt)
			if !ok {
				return true
			}
			// Check if the goroutine closure references loopVar
			funcLit, ok := goStmt.Call.Fun.(*ast.FuncLit)
			if !ok {
				return true
			}
			captures := false
			ast.Inspect(funcLit.Body, func(bodyNode ast.Node) bool {
				ident, ok := bodyNode.(*ast.Ident)
				if ok && ident.Name == loopVar {
					captures = true
					return false
				}
				return true
			})
			if captures {
				pos := c.fset.Position(goStmt.Pos())
				c.add(Finding{
					Antipattern:     "goroutine_closure_capture",
					AntipatternName: "Loop Variable Captured by Goroutine",
					Category:        "concurrency",
					Severity:        "high",
					Confidence:      0.9,
					LineStart:       pos.Line,
					LineEnd:         pos.Line,
					Message:         fmt.Sprintf("Goroutine closure captures loop variable '%s'. All goroutines will see the final value of '%s', not the value at iteration time.", loopVar, loopVar),
					Remediation:     fmt.Sprintf("Pass '%s' as an argument to the closure: go func(%s type) { ... }(%s)", loopVar, loopVar, loopVar),
					Effort:          "minutes",
					RuleID:          "go/goroutine-closure-capture",
					References:      []string{"https://go.dev/doc/faq#closures_and_goroutines"},
					Tags:            []string{"concurrency", "bugs", "race-condition"},
				})
			}
			return true
		})
		return true
	})
}

// ============================================================================
// CHECK: TLS InsecureSkipVerify
// ============================================================================

func (c *checker) checkTLSInsecureSkip(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		ident, ok := kv.Key.(*ast.Ident)
		if !ok || ident.Name != "InsecureSkipVerify" {
			return true
		}
		valIdent, ok := kv.Value.(*ast.Ident)
		if !ok || valIdent.Name != "true" {
			return true
		}
		pos := c.fset.Position(kv.Pos())
		c.add(Finding{
			Antipattern:     "tls_insecure_skip",
			AntipatternName: "TLS InsecureSkipVerify",
			Category:        "security",
			Severity:        "critical",
			Confidence:      1.0,
			LineStart:       pos.Line,
			LineEnd:         pos.Line,
			Message:         "InsecureSkipVerify is set to true. This disables TLS certificate verification and allows man-in-the-middle attacks.",
			Remediation:     "Remove InsecureSkipVerify: true, or set it to false. Use proper CA certificates for TLS validation.",
			Effort:          "minutes",
			RuleID:          "go/tls-insecure-skip",
			References:      []string{"https://pkg.go.dev/crypto/tls#Config"},
			Tags:            []string{"security", "tls", "owasp-a07"},
		})
		return true
	})
}

// ============================================================================
// CHECK: SQL string concatenation
// ============================================================================

func (c *checker) checkSQLStringConcat(file *ast.File) {
	sqlMethods := map[string]bool{"Query": true, "Exec": true, "QueryRow": true}

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !sqlMethods[sel.Sel.Name] {
			return true
		}
		if len(call.Args) == 0 {
			return true
		}
		// Check if the first argument is a string concatenation (BinaryExpr with +)
		binExpr, ok := call.Args[0].(*ast.BinaryExpr)
		if !ok || binExpr.Op != token.ADD {
			return true
		}
		pos := c.fset.Position(call.Pos())
		c.add(Finding{
			Antipattern:     "sql_string_concat",
			AntipatternName: "SQL String Concatenation",
			Category:        "security",
			Severity:        "high",
			Confidence:      0.85,
			LineStart:       pos.Line,
			LineEnd:         pos.Line,
			Message:         fmt.Sprintf("String concatenation used in %s() query argument. This is a SQL injection vector.", sel.Sel.Name),
			Remediation:     fmt.Sprintf("Use parameterized queries: db.%s(\"SELECT * FROM t WHERE id = $1\", userID)", sel.Sel.Name),
			Effort:          "minutes",
			RuleID:          "go/sql-string-concat",
			References:      []string{"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
			Tags:            []string{"security", "sql-injection", "owasp-a03"},
		})
		return true
	})
}

// ============================================================================
// CHECK: Weak rand usage in security context
// ============================================================================

func (c *checker) checkWeakRand(file *ast.File) {
	// Check if file imports crypto or contains security-sensitive variable names
	hasCryptoImport := false
	for _, imp := range file.Imports {
		if imp.Path != nil && strings.Contains(imp.Path.Value, "crypto") {
			hasCryptoImport = true
			break
		}
	}

	// Check for security-sensitive variable names in the file
	sensitiveNames := false
	sensitiveKeywords := []string{"token", "secret", "password", "key"}
	ast.Inspect(file, func(n ast.Node) bool {
		if sensitiveNames {
			return false
		}
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		lower := strings.ToLower(ident.Name)
		for _, kw := range sensitiveKeywords {
			if strings.Contains(lower, kw) {
				sensitiveNames = true
				return false
			}
		}
		return true
	})

	if !hasCryptoImport && !sensitiveNames {
		return
	}

	// Now look for math/rand usage
	randMethods := map[string]bool{
		"Intn": true, "Int": true, "Float64": true, "Float32": true,
		"Int31": true, "Int31n": true, "Int63": true, "Int63n": true,
		"Uint32": true, "Uint64": true,
	}

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "rand" {
			return true
		}
		if !randMethods[sel.Sel.Name] {
			return true
		}
		pos := c.fset.Position(call.Pos())
		c.add(Finding{
			Antipattern:     "weak_rand",
			AntipatternName: "Weak Random Number Generator",
			Category:        "security",
			Severity:        "high",
			Confidence:      0.75,
			LineStart:       pos.Line,
			LineEnd:         pos.Line,
			Message:         fmt.Sprintf("math/rand.%s() used in a file with security-sensitive context. math/rand is not cryptographically secure.", sel.Sel.Name),
			Remediation:     "Use crypto/rand instead: e.g., crypto/rand.Read() or crypto/rand.Int() for security-sensitive random values.",
			Effort:          "minutes",
			RuleID:          "go/weak-rand",
			References:      []string{"https://pkg.go.dev/crypto/rand"},
			Tags:            []string{"security", "cryptography"},
		})
		return true
	})
}

// ============================================================================
// Helpers
// ============================================================================

func exprName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprName(e.X) + "." + e.Sel.Name
	default:
		return "<expr>"
	}
}

func receiverTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return receiverTypeName(e.X)
	case *ast.Ident:
		return e.Name
	default:
		return ""
	}
}

func isEmptyInterface(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.InterfaceType:
		return e.Methods == nil || len(e.Methods.List) == 0
	case *ast.Ident:
		return e.Name == "any"
	default:
		return false
	}
}

func isContextType(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "context" && sel.Sel.Name == "Context"
}

func countStatements(block *ast.BlockStmt) int {
	count := 0
	ast.Inspect(block, func(n ast.Node) bool {
		switch n.(type) {
		case ast.Stmt:
			count++
		}
		return true
	})
	return count
}

// ============================================================================
// File scanning
// ============================================================================

func scanFile(fset *token.FileSet, filePath, repoRoot string) []Finding {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	f, err := parser.ParseFile(fset, filePath, src, parser.ParseComments)
	if err != nil {
		return nil
	}

	relPath, _ := filepath.Rel(repoRoot, filePath)
	c := &checker{fset: fset, file: relPath, source: src}

	c.checkUncheckedErrors(f)
	c.checkBareGoroutines(f)
	c.checkDeepNesting(f)
	c.checkGodStruct(f)
	c.checkMagicNumbers(f)
	c.checkEmptyInterfaceAbuse(f)
	c.checkContextFirstParam(f)
	c.checkLargeInterface(f)
	c.checkInitSideEffects(f)
	c.checkDeferInLoop(f)
	c.checkErrorStringFormat(f)
	c.checkGoroutineClosureCapture(f)
	c.checkTLSInsecureSkip(f)
	c.checkSQLStringConcat(f)
	c.checkWeakRand(f)

	return c.findings
}

func scanDirectory(root string, ignorePrefixes []string) []Finding {
	var findings []Finding
	fset := token.NewFileSet()

	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] || strings.HasPrefix(info.Name(), ".") {
				return filepath.SkipDir
			}
			rel, _ := filepath.Rel(root, path)
			for _, prefix := range ignorePrefixes {
				if strings.HasPrefix(rel, prefix) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".go") {
			return nil
		}
		// Skip test files for magic number checks (tests legitimately use literals)
		findings = append(findings, scanFile(fset, path, root)...)
		return nil
	})

	return findings
}

// ============================================================================
// CLI
// ============================================================================

func main() {
	// Manual arg parsing to support both `<path> --output <file>` and `--output <file> <path>`
	var rootPath, outputArg, ignoreArg string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--output":
			if i+1 < len(args) {
				outputArg = args[i+1]
				i++
			}
		case "--ignore":
			if i+1 < len(args) {
				ignoreArg = args[i+1]
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "-") && rootPath == "" {
				rootPath = args[i]
			}
		}
	}

	if rootPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: ast_checks <path> [--output <file>] [--ignore <prefixes>]")
		os.Exit(1)
	}

	var ignorePrefixes []string
	if ignoreArg != "" {
		for _, p := range strings.Split(ignoreArg, ",") {
			if t := strings.TrimSpace(p); t != "" {
				ignorePrefixes = append(ignorePrefixes, t)
			}
		}
	}

	findings := scanDirectory(rootPath, ignorePrefixes)

	result := Result{Findings: findings, Count: len(findings)}

	var outPath string
	if outputArg != "" {
		outPath = outputArg
	} else {
		f, err := os.CreateTemp("", "go_ast_findings_*.json")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create temp file: %v\n", err)
			os.Exit(1)
		}
		outPath = f.Name()
		f.Close()
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Go AST checker found %d findings -> %s\n", len(findings), outPath)
}

func init() {
	rand.New(rand.NewSource(time.Now().UnixNano()))
}
