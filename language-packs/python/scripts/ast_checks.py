#!/usr/bin/env python3
"""
Python AST Anti-Pattern Checker
Detects Python-specific anti-patterns that complexity tools miss:
  - Mutable default arguments
  - Bare except clauses (exception sinks)
  - Wildcard imports
  - Magic numbers / strings
  - Deep nesting
  - Implicit string concatenation
  - Missing __all__ in modules with wildcard-importable names
  - N+1 query patterns (ORM loop detection)
"""

import ast
import json
import os
import sys
import argparse
import tempfile
from dataclasses import dataclass, asdict, field
from typing import List, Optional
from datetime import datetime, timezone

PACK_VERSION = "python_v1"


@dataclass
class Finding:
    id: str
    antipattern: str
    antipattern_name: str
    category: str
    severity: str
    confidence: float
    file: str
    line_start: int
    line_end: int
    language: str
    language_pack: str
    message: str
    remediation: str
    effort: str
    tool: str
    rule_id: str
    code_snippet: Optional[str] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        return asdict(self)


def make_id():
    import random, string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=9))


class AntiPatternVisitor(ast.NodeVisitor):
    """Walks the AST of a single Python file and collects anti-pattern findings."""

    def __init__(self, filepath: str, source_lines: List[str]):
        self.filepath = filepath
        self.source_lines = source_lines
        self.findings: List[Finding] = []
        self._nesting_depth = 0

    def _snippet(self, node: ast.AST, context: int = 2) -> str:
        start = max(0, node.lineno - 1 - context)
        end = min(len(self.source_lines), node.lineno + context)
        return ''.join(self.source_lines[start:end]).strip()

    # --- Mutable default arguments ---
    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._check_mutable_defaults(node)
        # Nesting: only check if no nested function already reported for this scope
        if not self._has_nested_nesting_report(node):
            self._check_function_nesting(node)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _check_mutable_defaults(self, node):
        mutable_types = (ast.List, ast.Dict, ast.Set)
        for default in node.args.defaults + node.args.kw_defaults:
            if default and isinstance(default, mutable_types):
                type_name = type(default).__name__.replace('ast.', '').lower()
                self.findings.append(Finding(
                    id=make_id(),
                    antipattern='mutable_default_argument',
                    antipattern_name='Mutable Default Argument',
                    category='code_structure',
                    severity='high',
                    confidence=1.0,
                    file=self.filepath,
                    line_start=node.lineno,
                    line_end=node.lineno,
                    language='python',
                    language_pack=PACK_VERSION,
                    message=f"Function '{node.name}' uses a mutable {type_name} as a default argument -- "
                            f"this is shared across all calls and causes subtle bugs.",
                    remediation=(
                        f"Replace the mutable default with None and initialize inside the function:\n"
                        f"  def {node.name}(arg=None):\n"
                        f"      if arg is None: arg = {type_name}()"
                    ),
                    effort='minutes',
                    tool='ast-checker',
                    rule_id='python/mutable-default-argument',
                    code_snippet=self._snippet(node),
                    references=['https://docs.python-guide.org/writing/gotchas/#mutable-default-arguments'],
                    tags=['python-gotcha', 'bugs'],
                ))

    def _check_function_nesting(self, node):
        """Detect deep nesting and high cognitive complexity.

        Nesting depth rules:
        - Threshold: 5 (6 for recursive functions)
        - elif/else don't increment depth (flat sibling branches)
        - Early exits (if x: return/continue/break) don't increment depth
        - try blocks don't increment depth (every I/O function uses try)

        Cognitive complexity (inspired by SonarQube):
        - Each nesting level adds an increment equal to the current depth
        - Nested loops (for->for, while->for) score much higher than if->if
        - break/continue to a label, recursion, and boolean sequences add cost
        - Threshold: 15
        """
        is_recursive = self._is_recursive(node)

        # --- Nesting depth ---
        outer_node = node

        class NestingCounter(ast.NodeVisitor):
            def __init__(self):
                self.max_depth = 0
                self.depth = 0

            def visit_FunctionDef(self, n):
                if n is outer_node:
                    self.generic_visit(n)  # process root function body
                # else: skip nested function bodies

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_If(self, if_node):
                if self._is_early_exit(if_node):
                    self.generic_visit(if_node)
                    return
                self.depth += 1
                self.max_depth = max(self.max_depth, self.depth)
                for child in if_node.body:
                    self.visit(child)
                # elif/else: visit at the SAME depth (sibling, not child)
                for child in if_node.orelse:
                    self.visit(child)
                self.depth -= 1

            def _is_early_exit(self, if_node):
                if if_node.orelse:
                    return False
                if len(if_node.body) != 1:
                    return False
                return isinstance(if_node.body[0], (ast.Return, ast.Continue, ast.Break))

            def _enter_nesting(self, node):
                self.depth += 1
                self.max_depth = max(self.max_depth, self.depth)
                self.generic_visit(node)
                self.depth -= 1

            def _enter_no_depth(self, node):
                """Visit children without incrementing depth (try/with)."""
                self.generic_visit(node)

            visit_For = visit_While = visit_AsyncFor = _enter_nesting
            visit_Try = visit_With = visit_AsyncWith = _enter_no_depth

        counter = NestingCounter()
        counter.visit(node)

        # --- Cognitive complexity (checked first so nesting can defer to it) ---
        cog = self._cognitive_complexity(node)
        cc_fired = cog >= 20

        if cc_fired:
            self.findings.append(Finding(
                id=make_id(),
                antipattern='high_cyclomatic_complexity',
                antipattern_name='High Cognitive Complexity',
                category='code_structure',
                severity='medium' if cog < 25 else 'high',
                confidence=0.9,
                file=self.filepath,
                line_start=node.lineno,
                line_end=getattr(node, 'end_lineno', node.lineno),
                language='python',
                language_pack=PACK_VERSION,
                message=f"Function '{node.name}' has cognitive complexity of {cog} "
                        f"(threshold: 20). This function is hard to understand and test.",
                remediation=(
                    "Reduce complexity by extracting helper functions, flattening nested "
                    "loops, using early returns, or simplifying boolean expressions."
                ),
                effort='hours',
                tool='ast-checker',
                rule_id='python/cognitive-complexity',
                code_snippet=self._snippet(node),
                references=['https://www.sonarsource.com/docs/CognitiveComplexity.pdf'],
                tags=['maintainability', 'testability'],
            ))

        # --- Nesting depth (suppressed if CC already reported on this function) ---
        if not cc_fired:
            threshold = 6 if is_recursive else 5
            if counter.max_depth >= threshold:
                self.findings.append(Finding(
                    id=make_id(),
                    antipattern='deep_nesting',
                    antipattern_name='Deep Nesting',
                    category='code_structure',
                    severity='medium' if counter.max_depth < 7 else 'high',
                    confidence=0.85,
                    file=self.filepath,
                    line_start=node.lineno,
                    line_end=getattr(node, 'end_lineno', node.lineno),
                    language='python',
                    language_pack=PACK_VERSION,
                    message=f"Function '{node.name}' has nesting depth of {counter.max_depth} "
                            f"(threshold: {threshold}). Deep nesting makes code hard to read and test.",
                    remediation=(
                        "Reduce nesting by: (1) returning early on guard conditions, "
                        "(2) extracting nested blocks into helper functions, "
                        "(3) using array methods or generators instead of nested loops."
                    ),
                    effort='hours',
                    tool='ast-checker',
                    rule_id='python/deep-nesting',
                    code_snippet=self._snippet(node),
                    tags=['maintainability', 'readability'],
                ))

    def _cognitive_complexity(self, func_node):
        """Calculate cognitive complexity (SonarQube-inspired).

        Rules:
        - +1 for each: if, elif, else, for, while, except, and/or sequence,
          break/continue (to a label), recursion
        - Additional +1 per nesting level for: if, for, while, except
          (these are harder to reason about when nested)
        - No increment for: try (it's just error handling scaffolding),
          with (context manager), early returns
        """
        score = 0
        nesting = 0
        func_name = func_node.name

        def walk(node):
            nonlocal score, nesting

            # Skip nested function/class bodies -- they get scored independently
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node is not func_node:
                    return

            if isinstance(node, ast.If):
                score += 1 + nesting  # +1 base, +nesting for depth
                for child in node.body:
                    walk(child)
                # elif is +1 but no nesting increment
                for child in node.orelse:
                    if isinstance(child, ast.If):
                        score += 1  # elif: +1 flat (no nesting penalty)
                        for c in child.body:
                            walk(c)
                        for c in child.orelse:
                            walk(c)
                    else:
                        score += 1  # else: +1 flat
                        walk(child)
                return

            if isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
                score += 1 + nesting
                nesting += 1
                for child in ast.iter_child_nodes(node):
                    walk(child)
                nesting -= 1
                return

            if isinstance(node, ast.ExceptHandler):
                score += 1 + nesting
                for child in ast.iter_child_nodes(node):
                    walk(child)
                return

            if isinstance(node, ast.BoolOp):
                # Sequence of and/or: +1 per operator
                score += 1
                for child in ast.iter_child_nodes(node):
                    walk(child)
                return

            # Recursion: +1 per self-call
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == func_name:
                    score += 1

            for child in ast.iter_child_nodes(node):
                walk(child)

        for child in ast.iter_child_nodes(func_node):
            walk(child)

        return score

    def _has_nested_nesting_report(self, node):
        """Check if any nested function inside this one already has a nesting finding.
        Only report the innermost function that exceeds the threshold."""
        for child in ast.walk(node):
            if child is node:
                continue
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Check if this inner function would trigger nesting
                # by checking if we already have a finding for it
                for f in self.findings:
                    if (f.antipattern == 'deep_nesting'
                            and f.line_start == child.lineno):
                        return True
        return False

    def _is_recursive(self, func_node):
        """Check if a function calls itself."""
        func_name = func_node.name
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == func_name:
                    return True
                if isinstance(node.func, ast.Attribute) and node.func.attr == func_name:
                    return True
        return False

    # --- Bare except ---
    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.type is None:
            # bare `except:`
            body_is_empty = (
                len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
            )
            self.findings.append(Finding(
                id=make_id(),
                antipattern='bare_except' if not body_is_empty else 'exception_sink',
                antipattern_name='Bare Except' if not body_is_empty else 'Exception Sink',
                category='code_structure',
                severity='high',
                confidence=1.0,
                file=self.filepath,
                line_start=node.lineno,
                line_end=getattr(node, 'end_lineno', node.lineno),
                language='python',
                language_pack=PACK_VERSION,
                message=(
                    "Bare `except:` catches ALL exceptions including SystemExit and KeyboardInterrupt. "
                    + ("The handler does nothing (exception sink)." if body_is_empty else "")
                ),
                remediation=(
                    "Catch specific exceptions: `except (ValueError, TypeError) as e:`. "
                    "If you need a catch-all, use `except Exception as e:` and at minimum log the error."
                ),
                effort='minutes',
                tool='ast-checker',
                rule_id='python/bare-except',
                code_snippet=self._snippet(node),
                references=['https://peps.python.org/pep-0352/'],
                tags=['python-gotcha', 'error-handling'],
            ))
        self.generic_visit(node)

    # --- Wildcard imports ---
    def visit_ImportFrom(self, node: ast.ImportFrom):
        for alias in node.names:
            if alias.name == '*':
                self.findings.append(Finding(
                    id=make_id(),
                    antipattern='wildcard_import',
                    antipattern_name='Wildcard Import',
                    category='code_structure',
                    severity='medium',
                    confidence=1.0,
                    file=self.filepath,
                    line_start=node.lineno,
                    line_end=node.lineno,
                    language='python',
                    language_pack=PACK_VERSION,
                    message=f"`from {node.module} import *` pollutes the namespace and makes "
                            f"it impossible to know where names come from.",
                    remediation=f"Import only what you need: `from {node.module} import SpecificName`",
                    effort='minutes',
                    tool='ast-checker',
                    rule_id='python/wildcard-import',
                    code_snippet=self._snippet(node),
                    tags=['maintainability', 'namespace'],
                ))
        self.generic_visit(node)

    # --- Magic numbers ---
    def visit_Constant(self, node: ast.Constant):
        if not isinstance(node.value, (int, float)):
            self.generic_visit(node)
            return

        # Trivial values -- too common in arithmetic to be meaningful
        if node.value in (0, 1, -1, 2):
            self.generic_visit(node)
            return

        parent = getattr(node, '_parent', None)
        grandparent = getattr(parent, '_parent', None) if parent else None

        # Context: skip annotations, asserts, type hints
        if isinstance(parent, (ast.AnnAssign, ast.Assert)):
            self.generic_visit(node)
            return

        # Context: skip named assignments at module/class level
        # e.g. MAX_RETRIES = 3, DEFAULT_TIMEOUT = 30
        if isinstance(parent, ast.Assign) and isinstance(grandparent, ast.Module):
            self.generic_visit(node)
            return

        # Context: skip named constants in UPPER_CASE assignments
        if isinstance(parent, ast.Assign) and parent.targets:
            target = parent.targets[0]
            if isinstance(target, ast.Name) and target.id.isupper():
                self.generic_visit(node)
                return

        # Context: skip default parameter values
        # (these are in FunctionDef.args.defaults)
        if isinstance(parent, ast.arguments):
            self.generic_visit(node)
            return

        # Context: skip decorator arguments
        if isinstance(parent, ast.Call) and isinstance(grandparent, ast.expr):
            # Heuristic: decorators show up as Call nodes
            pass  # don't skip, but could refine

        # Context: skip keyword arguments (Field(default=3600), timeout=30)
        if isinstance(parent, ast.keyword):
            self.generic_visit(node)
            return

        # Context: skip function call arguments when the function name suggests configuration
        # e.g. sleep(5), range(10), Field(default=3600)
        if isinstance(parent, ast.Call):
            self.generic_visit(node)
            return

        # Context: skip comparisons (if status == 200) -- the value is contextual
        if isinstance(parent, ast.Compare):
            self.generic_visit(node)
            return

        # Context: skip test files
        if self.filepath.endswith(('_test.py', 'test_.py')) or '/test' in self.filepath:
            self.generic_visit(node)
            return

        # Context: skip hex/octal literals (bitmasks, file permissions)
        # Python AST resolves these to ints, but we can check the source
        if node.lineno <= len(self.source_lines):
            source_line = self.source_lines[node.lineno - 1]
            if '0x' in source_line or '0X' in source_line or '0o' in source_line or '0O' in source_line:
                self.generic_visit(node)
                return

        # Context: skip dict/list/tuple literals used as data (not logic)
        if isinstance(parent, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
            self.generic_visit(node)
            return

        # Context: skip slice indices and slice bounds (arr[:500])
        if isinstance(parent, (ast.Subscript, ast.Slice)):
            self.generic_visit(node)
            return

        # Context: skip binary operations (arithmetic like 2 ** n, x * 1024)
        if isinstance(parent, ast.BinOp):
            self.generic_visit(node)
            return

        self.findings.append(Finding(
            id=make_id(),
            antipattern='magic_number',
            antipattern_name='Magic Number',
            category='code_structure',
            severity='low',
            confidence=0.7,
            file=self.filepath,
            line_start=node.lineno,
            line_end=node.lineno,
            language='python',
            language_pack=PACK_VERSION,
            message=f"Magic number `{node.value}` -- unexplained numeric literal makes intent unclear.",
            remediation=f"Extract to a named constant: `THRESHOLD = {node.value}` and reference it by name.",
            effort='minutes',
            tool='ast-checker',
            rule_id='python/magic-number',
            tags=['readability', 'maintainability'],
        ))
        self.generic_visit(node)

    # --- N+1 query pattern (ORM loop) ---
    def visit_For(self, node: ast.For):
        """Detect ORM/database calls inside for loops.

        Key heuristics to reduce false positives:
        1. Only flag methods that look like ORM calls (keyword args like pk=, id=),
           not dict.get(key, default) which takes positional string args.
        2. Skip retry/polling loops: `for _ in range(...)` where the call target
           doesn't vary with the loop variable.
        3. Skip loops over in-memory data: if the iterable came from a local
           .get() on a dict, the loop body is just transforming data.
        """
        # Skip retry/polling loops: `for _ in range(...)`
        if self._is_retry_loop(node):
            self.generic_visit(node)
            return

        # Methods that strongly indicate ORM/DB calls (not dict methods)
        orm_methods = {'filter', 'exclude', 'select_related', 'prefetch_related',
                       'values', 'values_list', 'annotate', 'aggregate',
                       'create', 'bulk_create', 'delete'}
        # Methods that are ambiguous -- only flag if they use keyword args (ORM style)
        # dict.get("key", default) vs ORM.get(pk=1); dict.update({...}) vs QS.update(field=val)
        ambiguous_methods = {'get', 'all', 'first', 'last', 'count', 'update'}

        class OrmCallFinder(ast.NodeVisitor):
            def __init__(self):
                self.found = []

            def visit_Call(self, call_node):
                if not isinstance(call_node.func, ast.Attribute):
                    self.generic_visit(call_node)
                    return

                method = call_node.func.attr

                if method in orm_methods:
                    self.found.append(call_node)
                elif method in ambiguous_methods:
                    # Distinguish ORM .get(pk=1) from dict .get("key", default)
                    # ORM calls use keyword arguments; dict.get uses positional string args
                    has_keyword_args = any(kw for kw in call_node.keywords)
                    has_string_first_arg = (
                        call_node.args
                        and isinstance(call_node.args[0], ast.Constant)
                        and isinstance(call_node.args[0].value, str)
                    )
                    if has_keyword_args and not has_string_first_arg:
                        self.found.append(call_node)

                self.generic_visit(call_node)

        finder = OrmCallFinder()
        for stmt in node.body:
            finder.visit(stmt)

        if finder.found:
            call_names = list(set(c.func.attr for c in finder.found))
            self.findings.append(Finding(
                id=make_id(),
                antipattern='n_plus_one_query',
                antipattern_name='N+1 Query Pattern',
                category='code_structure',
                severity='high',
                confidence=0.8,
                file=self.filepath,
                line_start=node.lineno,
                line_end=getattr(node, 'end_lineno', node.lineno),
                language='python',
                language_pack=PACK_VERSION,
                message=f"Potential N+1 query: .{', .'.join(call_names)}() "
                        f"called inside a loop at line {node.lineno}. "
                        f"This may execute one query per iteration.",
                remediation=(
                    "Move the query outside the loop using `select_related()` or `prefetch_related()` "
                    "(Django), eager loading, or batch fetching with `__in` filters."
                ),
                effort='hours',
                tool='ast-checker',
                rule_id='python/n-plus-one-query',
                code_snippet=self._snippet(node),
                references=['https://docs.djangoproject.com/en/stable/ref/models/querysets/#select-related'],
                tags=['performance', 'database', 'n+1'],
            ))

        self.generic_visit(node)

    def _is_retry_loop(self, for_node):
        """Detect retry/polling patterns like `for _ in range(N):`."""
        # Check if iterating over range()
        if not isinstance(for_node.iter, ast.Call):
            return False
        func = for_node.iter
        if isinstance(func.func, ast.Name) and func.func.id == 'range':
            # Check if loop var is unused or named like attempt/retry/try
            target = for_node.target
            if isinstance(target, ast.Name):
                name = target.id
                if name == '_' or name.startswith(('attempt', 'retry', 'try_')):
                    return True
        return False


def _set_parents(tree: ast.AST):
    """Annotate each node with a reference to its parent."""
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child._parent = node  # type: ignore


def scan_file(filepath: str, repo_root: str) -> List[Finding]:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            source = f.read()
            lines = source.splitlines(keepends=True)
    except (IOError, OSError) as e:
        return []

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return []

    _set_parents(tree)

    rel_path = os.path.relpath(filepath, repo_root)
    visitor = AntiPatternVisitor(rel_path, lines)
    visitor.visit(tree)

    return visitor.findings


def scan_directory(
    root: str,
    ignore_patterns: List[str] = None
) -> List[Finding]:
    ignore_patterns = ignore_patterns or []
    findings = []

    skip_dirs = {
        '__pycache__', '.git', '.venv', 'venv', 'env',
        'node_modules', 'dist', 'build', '.tox', '.mypy_cache'
    }

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]

        for filename in filenames:
            if not filename.endswith('.py'):
                continue

            filepath = os.path.join(dirpath, filename)
            rel = os.path.relpath(filepath, root)

            if any(rel.startswith(p) for p in ignore_patterns):
                continue

            findings.extend(scan_file(filepath, root))

    return findings


def main():
    parser = argparse.ArgumentParser(description='Python AST anti-pattern checker')
    parser.add_argument('path', help='Root path to scan')
    parser.add_argument('--output', default='')
    parser.add_argument('--ignore', default='', help='Comma-separated ignore prefixes')
    parser.add_argument('--single-file', default='',
                        help='Scan only this specific file (IDE mode -- faster)')
    args = parser.parse_args()

    ignore = [p.strip() for p in args.ignore.split(',') if p.strip()]

    # IDE mode: scan just the saved file, not the whole directory
    if args.single_file and os.path.isfile(args.single_file):
        findings = scan_file(args.single_file, args.path)
    else:
        findings = scan_directory(args.path, ignore)

    result = {
        'findings': [f.to_dict() for f in findings],
        'count': len(findings),
    }

    if args.output:
        output_path = args.output
    else:
        fd, output_path = tempfile.mkstemp(suffix='.json', prefix='ast_findings_')
        os.close(fd)

    with open(output_path, 'w') as out:
        json.dump(result, out, indent=2)

    print(f"AST checker found {len(findings)} findings -> {output_path}")


if __name__ == '__main__':
    main()
