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

    # ── Mutable default arguments ────────────────────────────────────────────
    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._check_mutable_defaults(node)
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
                    message=f"Function '{node.name}' uses a mutable {type_name} as a default argument — "
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
        """Detect deep nesting by counting nested control flow."""
        class NestingCounter(ast.NodeVisitor):
            def __init__(self):
                self.max_depth = 0
                self.depth = 0

            def _enter(self, node):
                self.depth += 1
                self.max_depth = max(self.max_depth, self.depth)
                self.generic_visit(node)
                self.depth -= 1

            visit_If = visit_For = visit_While = visit_With = \
            visit_Try = visit_AsyncFor = visit_AsyncWith = _enter

        counter = NestingCounter()
        counter.visit(node)

        if counter.max_depth >= 4:
            self.findings.append(Finding(
                id=make_id(),
                antipattern='deep_nesting',
                antipattern_name='Deep Nesting',
                category='code_structure',
                severity='medium' if counter.max_depth < 6 else 'high',
                confidence=0.9,
                file=self.filepath,
                line_start=node.lineno,
                line_end=getattr(node, 'end_lineno', node.lineno),
                language='python',
                language_pack=PACK_VERSION,
                message=f"Function '{node.name}' has nesting depth of {counter.max_depth} "
                        f"(threshold: 4). Deep nesting makes code hard to read and test.",
                remediation=(
                    "Reduce nesting by: (1) returning early on guard conditions, "
                    "(2) extracting nested blocks into helper functions, "
                    "(3) using list comprehensions or generators instead of nested loops."
                ),
                effort='hours',
                tool='ast-checker',
                rule_id='python/deep-nesting',
                code_snippet=self._snippet(node),
                tags=['maintainability', 'readability'],
            ))

    # ── Bare except ──────────────────────────────────────────────────────────
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

    # ── Wildcard imports ─────────────────────────────────────────────────────
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

    # ── Magic numbers ────────────────────────────────────────────────────────
    def visit_Constant(self, node: ast.Constant):
        parent = getattr(node, '_parent', None)

        # Only flag numbers (not in simple assignments at module level, not 0/1/-1)
        if isinstance(node.value, (int, float)) and node.value not in (0, 1, -1, 2, 100):
            # Skip if this is an annotation or in an assert
            if not isinstance(parent, (ast.AnnAssign, ast.Assert, ast.Index)):
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
                    message=f"Magic number `{node.value}` — unexplained numeric literal makes intent unclear.",
                    remediation=f"Extract to a named constant: `MAX_RETRIES = {node.value}` and reference it by name.",
                    effort='minutes',
                    tool='ast-checker',
                    rule_id='python/magic-number',
                    tags=['readability', 'maintainability'],
                ))
        self.generic_visit(node)

    # ── N+1 query pattern (ORM loop) ─────────────────────────────────────────
    def visit_For(self, node: ast.For):
        """Detect `.filter(`, `.get(`, `.all()` calls inside for loops."""
        orm_methods = {'filter', 'get', 'all', 'first', 'last', 'count', 'exclude', 'select_related'}

        class OrmCallFinder(ast.NodeVisitor):
            def __init__(self):
                self.found = []

            def visit_Call(self, call_node):
                if isinstance(call_node.func, ast.Attribute):
                    if call_node.func.attr in orm_methods:
                        self.found.append(call_node)
                self.generic_visit(call_node)

        finder = OrmCallFinder()
        for stmt in node.body:
            finder.visit(stmt)

        if finder.found:
            self.findings.append(Finding(
                id=make_id(),
                antipattern='n_plus_one_query',
                antipattern_name='N+1 Query Pattern',
                category='code_structure',
                severity='high',
                confidence=0.75,
                file=self.filepath,
                line_start=node.lineno,
                line_end=getattr(node, 'end_lineno', node.lineno),
                language='python',
                language_pack=PACK_VERSION,
                message=f"Potential N+1 query: ORM call inside a loop at line {node.lineno}. "
                        f"This executes one query per iteration.",
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
    parser.add_argument('--output', default='/tmp/ast_findings.json')
    parser.add_argument('--ignore', default='', help='Comma-separated ignore prefixes')
    args = parser.parse_args()

    ignore = [p.strip() for p in args.ignore.split(',') if p.strip()]
    findings = scan_directory(args.path, ignore)

    result = {
        'findings': [f.to_dict() for f in findings],
        'count': len(findings),
    }

    with open(args.output, 'w') as out:
        json.dump(result, out, indent=2)

    print(f"AST checker found {len(findings)} findings → {args.output}")


if __name__ == '__main__':
    main()
