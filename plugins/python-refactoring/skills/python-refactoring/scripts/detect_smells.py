#!/usr/bin/env python3
"""
Python Code Smell Detector — maps findings to the 82-pattern refactoring catalog.

Self-contained: stdlib only (ast, pathlib, sys, json, collections, re, textwrap).
Detects 55 patterns programmatically (40 per-file + 10 cross-file + 5 OO metrics).

Usage:
    python detect_smells.py path/to/file_or_dir [--json] [--min-severity info]
    python detect_smells.py src/ --json
    python detect_smells.py mymodule.py --min-severity warning
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
import textwrap
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Final

# ---------------------------------------------------------------------------
# Finding data model
# ---------------------------------------------------------------------------

SEVERITY_ORDER: Final = {"info": 0, "warning": 1, "error": 2}


@dataclass
class Finding:
    file: str
    line: int
    pattern: str  # e.g. "#001"
    name: str  # e.g. "Remove Setters"
    severity: str  # info | warning | error
    message: str
    category: str  # state | functions | types | control | architecture | hygiene | idioms | metrics

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)


# ---------------------------------------------------------------------------
# ClassInfo: per-class metadata for OO metrics (Tier 2/3)
# ---------------------------------------------------------------------------

@dataclass
class ClassInfo:
    name: str
    filepath: str
    line: int
    bases: list[str] = field(default_factory=list)
    method_count: int = 0
    field_count: int = 0
    all_fields: list[str] = field(default_factory=list)
    methods_using_fields: dict[str, set[str]] = field(default_factory=dict)  # method -> fields accessed
    external_class_accesses: dict[str, int] = field(default_factory=dict)  # other_class -> access count
    external_method_calls: set[str] = field(default_factory=set)  # "ClassName.method" distinct calls
    delegation_count: int = 0  # methods that just delegate to another object
    non_dunder_method_count: int = 0
    is_abstract: bool = False
    abstract_methods: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Thresholds (configurable)
# ---------------------------------------------------------------------------

# --- Original thresholds ---
MAX_FUNCTION_LINES: Final = 25
MAX_PARAMS: Final = 5
MAX_NESTING_DEPTH: Final = 3
MAX_DECORATORS: Final = 3
MAX_CLASS_METHODS: Final = 12
MAX_CYCLOMATIC_COMPLEXITY: Final = 10
MAX_MODULE_TOPLEVEL_DEFS: Final = 30
MIN_DUPLICATE_LINES: Final = 8
FEATURE_ENVY_THRESHOLD: Final = 3
HASH_PREFIX_LEN: Final = 12
SEPARATOR_WIDTH: Final = 60
MAGIC_NUMBER_WHITELIST: Final = frozenset({0, 1, -1, 2, 0.0, 1.0, 0.5, 100, 10})
GENERIC_NAMES: Final = frozenset({
    "result", "results", "res", "data", "tmp", "temp", "val", "ret",
    "output", "out", "obj", "item", "elem", "value", "info",
})

# --- Tier 1: new per-file thresholds ---
MAX_LAMBDA_LENGTH: Final = 60  # characters of unparsed source
MAX_COMPREHENSION_GENERATORS: Final = 2  # nested for-clauses
MIN_LAZY_CLASS_METHODS: Final = 2  # fewer non-dunder methods = lazy
TEMP_FIELD_USAGE_RATIO: Final = 0.3  # field used in <30% of methods

# --- Tier 2: cross-file thresholds ---
SHOTGUN_SURGERY_THRESHOLD: Final = 5  # called from >N different files
MAX_INHERITANCE_DEPTH: Final = 4
MAX_DIRECT_SUBCLASSES: Final = 5
INTIMACY_THRESHOLD: Final = 3  # shared attribute accesses between class pairs

# --- Tier 3: OO metrics thresholds ---
MAX_LCOM: Final = 0.8  # lack of cohesion > threshold
MAX_CBO: Final = 8  # coupling between objects
MAX_FANOUT: Final = 15  # outgoing module dependencies
MAX_RFC: Final = 20  # response for a class
MIDDLE_MAN_RATIO: Final = 0.5  # >50% delegation methods


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _lines_of(node: ast.AST) -> int:
    """Approximate line count of a node."""
    if hasattr(node, "end_lineno") and hasattr(node, "lineno"):
        return (node.end_lineno or node.lineno) - node.lineno + 1
    return 0


def _nesting_depth(node: ast.AST, _depth: int = 0) -> int:
    """Max nesting depth of control flow inside a node."""
    max_d = _depth
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
            max_d = max(max_d, _nesting_depth(child, _depth + 1))
        else:
            max_d = max(max_d, _nesting_depth(child, _depth))
    return max_d


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _is_mutable_literal(node: ast.AST) -> bool:
    return isinstance(node, (ast.List, ast.Dict, ast.Set))


def _get_assigned_names(targets: list[ast.AST]) -> list[str]:
    names = []
    for t in targets:
        if isinstance(t, ast.Name):
            names.append(t.id)
        elif isinstance(t, ast.Tuple | ast.List):
            names.extend(_get_assigned_names(t.elts))
    return names


def _cyclomatic_complexity(node: ast.AST) -> int:
    """Compute McCabe cyclomatic complexity of a function/method node."""
    cc = 1
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.IfExp)):
            cc += 1
        elif isinstance(child, (ast.For, ast.While, ast.AsyncFor)):
            cc += 1
        elif isinstance(child, ast.ExceptHandler):
            cc += 1
        elif isinstance(child, ast.With | ast.AsyncWith):
            cc += 1
        elif isinstance(child, ast.Assert):
            cc += 1
        elif isinstance(child, ast.BoolOp):
            cc += len(child.values) - 1
        elif isinstance(child, ast.comprehension):
            cc += 1
            cc += len(child.ifs)
    return cc


def _normalize_ast(node: ast.AST) -> str:
    """Produce a canonical string from an AST node for duplicate detection."""
    parts: list[str] = []

    def _walk(n: ast.AST):
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
            parts.append("DOC")
            return
        parts.append(type(n).__name__)
        for child in ast.iter_child_nodes(n):
            if isinstance(child, ast.arguments):
                parts.append(f"ARGS({len(child.args)})")
                continue
            if isinstance(child, ast.Name):
                parts.append("NAME")
                continue
            if isinstance(child, ast.Constant):
                parts.append(f"CONST({type(child.value).__name__})")
                continue
            _walk(child)

    _walk(node)
    return "|".join(parts)


def _extract_imports(tree: ast.Module) -> list[str]:
    """Extract all imported module names from a module's AST.

    Returns both the full dotted path and all intermediate segments so that
    cross-file matching works for both package-style imports (``from pkg.sub import x``)
    and flat single-file imports (``import utils``).
    """
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # "import pkg_a.a" → ["pkg_a", "a", "pkg_a.a"]
                parts = alias.name.split(".")
                imports.extend(parts)
                if len(parts) > 1:
                    imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                parts = node.module.split(".")
                imports.extend(parts)
                if len(parts) > 1:
                    imports.append(node.module)
    return imports


def _is_stub_body(body: list[ast.stmt]) -> bool:
    """Check if a function body is just pass, ..., or a docstring."""
    if not body:
        return True
    stmts = body
    # Skip leading docstring
    if (isinstance(stmts[0], ast.Expr) and isinstance(stmts[0].value, ast.Constant)
            and isinstance(stmts[0].value.value, str)):
        stmts = stmts[1:]
    if not stmts:
        return True  # docstring only
    if len(stmts) == 1:
        s = stmts[0]
        if isinstance(s, ast.Pass):
            return True
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and s.value.value is ...:
            return True
        if isinstance(s, ast.Raise):
            return True  # abstract-like raise NotImplementedError
    return False


def _has_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, names: set[str]) -> bool:
    """Check if a node has any decorator with the given names."""
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name) and dec.id in names:
            return True
        if isinstance(dec, ast.Attribute) and dec.attr in names:
            return True
        if isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name) and dec.func.id in names:
                return True
            if isinstance(dec.func, ast.Attribute) and dec.func.attr in names:
                return True
    return False


# ---------------------------------------------------------------------------
# Cross-file data collected during first pass
# ---------------------------------------------------------------------------

@dataclass
class FileData:
    """Per-file metadata collected during scanning for cross-file analysis."""
    filepath: str
    toplevel_defs: int = 0
    total_lines: int = 0
    imports: list[str] = field(default_factory=list)
    # func_key -> (filepath, func_name, line, normalized_hash, line_count)
    func_signatures: list[tuple[str, str, int, str, int]] = field(default_factory=list)
    # method -> {external_class: count}
    method_external_accesses: list[tuple[str, int, str, dict[str, int]]] = field(default_factory=list)
    # class names defined in this file
    class_names: list[str] = field(default_factory=list)
    # --- Tier 2/3 additions ---
    class_bases: dict[str, list[str]] = field(default_factory=dict)  # class -> base names
    class_lines: dict[str, int] = field(default_factory=dict)  # class -> line number
    class_info: list[ClassInfo] = field(default_factory=list)  # detailed class data
    defined_functions: set[str] = field(default_factory=set)  # all func/method names defined
    called_functions: set[str] = field(default_factory=set)  # all func names called
    abstract_classes: set[str] = field(default_factory=set)  # classes with ABC or abstract methods


# ---------------------------------------------------------------------------
# Detector: walks one file's AST
# ---------------------------------------------------------------------------


class SmellDetector(ast.NodeVisitor):
    def __init__(self, filepath: str, source: str):
        self.filepath = filepath
        self.source = source
        self.source_lines = source.splitlines()
        self.findings: list[Finding] = []

        # State tracking
        self._class_stack: list[ast.ClassDef] = []
        self._func_stack: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        self._class_attrs: dict[str, list[str]] = defaultdict(list)
        self._class_bool_attrs: dict[str, list[str]] = defaultdict(list)
        self._class_methods: dict[str, int] = Counter()
        self._open_calls_outside_with: list[tuple[int, str]] = []
        self._string_concat_lines: set[int] = set()

        # Cross-file data
        self.file_data = FileData(filepath=filepath, total_lines=len(source.splitlines()))

        # Tier 2/3: class-level collection
        self._current_class_info: ClassInfo | None = None
        self._class_all_fields: dict[str, list[str]] = defaultdict(list)  # class -> all self.x fields
        self._class_methods_fields: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    def _add(self, line: int, pattern: str, name: str, severity: str, message: str, category: str):
        self.findings.append(Finding(
            file=self.filepath, line=line, pattern=pattern,
            name=name, severity=severity, message=message, category=category,
        ))

    # =======================================================================
    # State & Immutability
    # =======================================================================

    def _check_setters(self, node: ast.FunctionDef):
        """#001 -- Remove Setters."""
        if (
            self._class_stack
            and node.name.startswith("set_")
            and len(node.args.args) == 2
        ):
            attr = node.name[4:]
            self._add(node.lineno, "#001", "Remove Setters", "warning",
                      f"Setter `{node.name}` -- consider making `{attr}` a constructor param or using @dataclass(frozen=True)",
                      "state")

    def _check_half_built_init(self, node: ast.FunctionDef):
        """#016 -- Build With The Essence: __init__ setting attrs to None."""
        if not (self._class_stack and node.name == "__init__"):
            return
        cls_name = self._class_stack[-1].name
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                        and _is_none(stmt.value)
                    ):
                        self._class_attrs[cls_name].append(target.attr)
            elif isinstance(stmt, ast.AnnAssign):
                if (
                    isinstance(stmt.target, ast.Attribute)
                    and isinstance(stmt.target.value, ast.Name)
                    and stmt.target.value.id == "self"
                    and stmt.value is not None
                    and _is_none(stmt.value)
                ):
                    self._class_attrs[cls_name].append(stmt.target.attr)

    def _check_bool_flag_attrs(self, node: ast.FunctionDef):
        """#017 -- Convert Attributes to Sets: multiple is_* booleans."""
        if not (self._class_stack and node.name == "__init__"):
            return
        cls_name = self._class_stack[-1].name
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                        and target.attr.startswith("is_")
                        and isinstance(stmt.value, ast.Constant)
                        and isinstance(stmt.value.value, bool)
                    ):
                        self._class_bool_attrs[cls_name].append(target.attr)

    def _check_public_attrs(self, node: ast.FunctionDef):
        """#009 -- Protect Public Attributes."""
        if not (self._class_stack and node.name == "__init__"):
            return
        public_attrs = []
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                        and not target.attr.startswith("_")
                    ):
                        public_attrs.append(target.attr)
        if len(public_attrs) >= 3:
            self._add(node.lineno, "#009", "Protect Public Attributes", "info",
                      f"Class `{self._class_stack[-1].name}` exposes {len(public_attrs)} public attrs: "
                      f"{', '.join(public_attrs[:5])}{'...' if len(public_attrs) > 5 else ''}",
                      "state")

    # =======================================================================
    # Functions & Methods
    # =======================================================================

    def _check_long_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#002 -- Extract Method: function too long."""
        lines = _lines_of(node)
        if lines > MAX_FUNCTION_LINES:
            self._add(node.lineno, "#002", "Extract Method", "warning",
                      f"`{node.name}` is {lines} lines (threshold: {MAX_FUNCTION_LINES})",
                      "functions")

    def _check_deep_nesting(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#039 -- Guard Clauses: deep nesting."""
        depth = _nesting_depth(node)
        if depth > MAX_NESTING_DEPTH:
            self._add(node.lineno, "#039", "Replace Nested Conditional with Guard Clauses", "warning",
                      f"`{node.name}` has nesting depth {depth} (threshold: {MAX_NESTING_DEPTH})",
                      "control")

    def _check_too_many_params(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#034 -- Reify Parameters: long parameter list."""
        args = node.args
        count = len(args.args) + len(args.posonlyargs) + len(args.kwonlyargs)
        if self._class_stack and args.args and args.args[0].arg in ("self", "cls"):
            count -= 1
        if count > MAX_PARAMS:
            self._add(node.lineno, "#034", "Reify Parameters", "warning",
                      f"`{node.name}` has {count} parameters (threshold: {MAX_PARAMS})",
                      "functions")

    def _check_generic_names(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#006 -- Rename Result Variables: generic names."""
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for name in _get_assigned_names(child.targets):
                    if name in GENERIC_NAMES:
                        self._add(child.lineno, "#006", "Rename Result Variables", "info",
                                  f"Generic variable name `{name}` in `{node.name}` -- use a descriptive name",
                                  "functions")

    def _check_cqs_violation(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#041 -- Separate Query from Modifier (CQS)."""
        if node.name.startswith("_") or not self._class_stack:
            return
        has_self_assignment = False
        has_return_value = False
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for t in child.targets:
                    if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self":
                        has_self_assignment = True
            if isinstance(child, ast.Return) and child.value is not None and not _is_none(child.value):
                has_return_value = True
        if has_self_assignment and has_return_value:
            self._add(node.lineno, "#041", "Separate Query from Modifier", "info",
                      f"`{node.name}` both mutates self and returns a value -- consider splitting",
                      "functions")

    def _check_excessive_decorators(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#033 -- Strip Annotations: too many decorators."""
        if len(node.decorator_list) > MAX_DECORATORS:
            self._add(node.lineno, "#033", "Strip Annotations", "info",
                      f"`{node.name}` has {len(node.decorator_list)} decorators (threshold: {MAX_DECORATORS})",
                      "hygiene")

    def _check_unused_params(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#064 -- Remove Unused Parameters."""
        if _is_stub_body(node.body):
            return
        if _has_decorator(node, {"abstractmethod", "override", "overload"}):
            return
        # Collect parameter names
        params: set[str] = set()
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            params.add(arg.arg)
        params -= {"self", "cls"}
        if node.args.vararg:
            params.discard(node.args.vararg.arg)
        if node.args.kwarg:
            params.discard(node.args.kwarg.arg)
        if not params:
            return
        # Collect all names used in body (skip docstring)
        used_names: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                used_names.add(child.id)
        # Parameter names appear as ast.arg, not ast.Name, in the signature
        # but ARE ast.Name when referenced in the body
        unused = params - used_names
        # Also skip _-prefixed params (convention for intentionally unused)
        unused = {p for p in unused if not p.startswith("_")}
        if unused:
            self._add(node.lineno, "#064", "Remove Unused Parameters", "warning",
                      f"`{node.name}` has unused parameters: {', '.join(sorted(unused))}",
                      "functions")

    def _check_long_lambda(self, node: ast.Lambda):
        """#066 -- Replace Long Lambda with Function."""
        try:
            source = ast.unparse(node)
        except Exception:
            return
        if len(source) > MAX_LAMBDA_LENGTH:
            self._add(node.lineno, "#066", "Replace Long Lambda with Function", "info",
                      f"Lambda is {len(source)} chars (threshold: {MAX_LAMBDA_LENGTH}) -- use a named function",
                      "functions")

    # =======================================================================
    # Type Design
    # =======================================================================

    def _check_isinstance_chain(self, node: ast.If):
        """#014/#060 -- Replace IF with Polymorphism."""
        isinstance_count = 0
        current: ast.AST | None = node
        while current is not None:
            if isinstance(current, ast.If):
                test = current.test
                if (isinstance(test, ast.Call)
                        and isinstance(test.func, ast.Name)
                        and test.func.id == "isinstance"):
                    isinstance_count += 1
                current = current.orelse[0] if (current.orelse and isinstance(current.orelse[0], ast.If)) else None
            else:
                break
        if isinstance_count >= 2:
            self._add(node.lineno, "#014", "Replace IF with Polymorphism", "warning",
                      f"isinstance chain with {isinstance_count} branches -- consider polymorphism or Protocol",
                      "types")

    def _check_lazy_class(self, node: ast.ClassDef):
        """#069 -- Remove Lazy Class: class too small to justify existence."""
        # Skip special base classes
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id in (
                "ABC", "Protocol", "Exception", "Enum", "IntEnum", "StrEnum",
                "TypedDict", "NamedTuple",
            ):
                return
            if isinstance(base, ast.Attribute) and base.attr in (
                "ABC", "Protocol", "Exception",
            ):
                return
        if _has_decorator(node, {"dataclass", "dataclasses"}):
            return
        # Count methods and fields
        method_count = 0
        non_dunder_count = 0
        field_count = 0
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_count += 1
                if not stmt.name.startswith("__"):
                    non_dunder_count += 1
                if stmt.name == "__init__":
                    for child in ast.walk(stmt):
                        if (isinstance(child, ast.Attribute)
                                and isinstance(child.value, ast.Name)
                                and child.value.id == "self"
                                and isinstance(child.ctx, ast.Store)):
                            field_count += 1
        # A class is lazy if it has very few methods and fields
        if non_dunder_count < MIN_LAZY_CLASS_METHODS and field_count < 2 and method_count > 0:
            self._add(node.lineno, "#069", "Remove Lazy Class", "info",
                      f"Class `{node.name}` has {non_dunder_count} non-dunder methods and {field_count} fields "
                      f"-- consider inlining or merging",
                      "types")

    def _check_temporary_fields(self, node: ast.ClassDef):
        """#070 -- Remove Temporary Field: fields used in few methods."""
        init_fields: set[str] = set()
        methods: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        for stmt in node.body:
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if stmt.name == "__init__":
                for child in ast.walk(stmt):
                    if (isinstance(child, ast.Attribute)
                            and isinstance(child.value, ast.Name)
                            and child.value.id == "self"
                            and isinstance(child.ctx, ast.Store)):
                        init_fields.add(child.attr)
            elif not stmt.name.startswith("__"):
                methods.append(stmt)

        if not init_fields or len(methods) < 3:
            return

        for field_name in init_fields:
            usage_count = 0
            for method in methods:
                for child in ast.walk(method):
                    if (isinstance(child, ast.Attribute)
                            and isinstance(child.value, ast.Name)
                            and child.value.id == "self"
                            and child.attr == field_name):
                        usage_count += 1
                        break
            ratio = usage_count / len(methods)
            if ratio < TEMP_FIELD_USAGE_RATIO:
                self._add(node.lineno, "#070", "Remove Temporary Field", "info",
                          f"`{node.name}.{field_name}` used in {usage_count}/{len(methods)} methods "
                          f"({ratio:.0%}) -- consider local variable or parameter",
                          "types")

    # =======================================================================
    # Control Flow
    # =======================================================================

    def _check_loop_append(self, node: ast.For | ast.While):
        """#040 -- Replace Loop with Pipeline."""
        for stmt in ast.walk(node):
            if (isinstance(stmt, ast.Expr)
                    and isinstance(stmt.value, ast.Call)
                    and isinstance(stmt.value.func, ast.Attribute)
                    and stmt.value.func.attr == "append"):
                self._add(node.lineno, "#040", "Replace Loop with Pipeline", "info",
                          "Loop with `.append()` -- consider list comprehension or generator",
                          "control")
                return

    def _check_control_flag(self, node: ast.For | ast.While):
        """#055 -- Replace Control Flag with Break."""
        parent_body = None
        if self._func_stack:
            parent_body = self._func_stack[-1].body
        if parent_body is None:
            return

        flag_names = set()
        for stmt in parent_body:
            if stmt is node:
                break
            if (isinstance(stmt, ast.Assign)
                    and len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Name)
                    and isinstance(stmt.value, ast.Constant)
                    and stmt.value.value is False):
                flag_names.add(stmt.targets[0].id)

        if not flag_names:
            return

        for child in ast.walk(node):
            if isinstance(child, ast.If):
                test = child.test
                if isinstance(test, ast.Name) and test.id in flag_names:
                    self._add(node.lineno, "#055", "Replace Control Flag with Break", "info",
                              f"Boolean flag `{test.id}` controls loop -- use `break`/`return`/`any()`",
                              "control")
                    return
                if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                    if isinstance(test.operand, ast.Name) and test.operand.id in flag_names:
                        self._add(node.lineno, "#055", "Replace Control Flag with Break", "info",
                                  f"Boolean flag `{test.operand.id}` controls loop -- use `break`/`return`/`any()`",
                                  "control")
                        return

    def _check_complex_boolean(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#042 -- Decompose Conditional."""
        def _count_bool_ops(expr: ast.AST) -> int:
            if isinstance(expr, ast.BoolOp):
                count = len(expr.values) - 1
                for v in expr.values:
                    count += _count_bool_ops(v)
                return count
            return 0

        for child in ast.walk(node):
            if isinstance(child, ast.If):
                ops = _count_bool_ops(child.test)
                if ops >= 3:
                    self._add(child.lineno, "#042", "Decompose Conditional", "warning",
                              f"Complex boolean ({ops} operators) in `{node.name}` -- extract to descriptive function",
                              "control")
                    return

    def _check_missing_else(self, node: ast.If):
        """#068 -- Add Default Else Branch: if/elif chain without else."""
        # Only flag top-level if statements (not nested inside elif)
        has_elif = False
        current = node
        branch_count = 1
        while current.orelse:
            if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
                has_elif = True
                branch_count += 1
                current = current.orelse[0]
            else:
                return  # has an else clause -- fine
        if has_elif and branch_count >= 2:
            self._add(node.lineno, "#068", "Add Default Else Branch", "info",
                      f"if/elif chain with {branch_count} branches but no default `else`",
                      "control")

    def _check_long_comprehension(self, node: ast.AST):
        """#067 -- Simplify Complex Comprehension: too many nested generators."""
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            if len(node.generators) > MAX_COMPREHENSION_GENERATORS:
                kind = {
                    ast.ListComp: "List comprehension",
                    ast.SetComp: "Set comprehension",
                    ast.GeneratorExp: "Generator expression",
                }.get(type(node), "Comprehension")
                self._add(node.lineno, "#067", "Simplify Complex Comprehension", "info",
                          f"{kind} has {len(node.generators)} nested loops -- simplify or use explicit loops",
                          "control")
        elif isinstance(node, ast.DictComp):
            if len(node.generators) > MAX_COMPREHENSION_GENERATORS:
                self._add(node.lineno, "#067", "Simplify Complex Comprehension", "info",
                          f"Dict comprehension has {len(node.generators)} nested loops -- simplify",
                          "control")

    # =======================================================================
    # Architecture
    # =======================================================================

    def _check_singleton(self, node: ast.ClassDef):
        """#018 -- Replace Singleton."""
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    if isinstance(t, ast.Name) and t.id == "_instance" and _is_none(stmt.value):
                        self._add(node.lineno, "#018", "Replace Singleton", "warning",
                                  f"Class `{node.name}` uses Singleton pattern -- consider dependency injection",
                                  "architecture")
                        return

    def _check_global_mutable(self, node: ast.Assign):
        """#024 -- Replace Global Variables with DI."""
        if self._class_stack or self._func_stack:
            return
        if isinstance(node.value, (ast.Call, ast.Dict, ast.List, ast.Set)):
            for name in _get_assigned_names(node.targets):
                if not name.startswith("_") and name != name.upper():
                    self._add(node.lineno, "#024", "Replace Global Variables with DI", "info",
                              f"Module-level mutable `{name}` -- consider dependency injection",
                              "architecture")

    def _check_constant_without_final(self, node: ast.Assign):
        """#008 -- Convert Variables to Constants."""
        if self._class_stack or self._func_stack:
            return
        for name in _get_assigned_names(node.targets):
            if name == name.upper() and name.startswith(tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZ")):
                self._add(node.lineno, "#008", "Convert Variables to Constants", "info",
                          f"`{name}` is UPPER_CASE but not annotated with `typing.Final`",
                          "state")

    def _check_sequential_ids(self, node: ast.ClassDef):
        """#028 -- Replace Sequential IDs."""
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    if isinstance(t, ast.Name) and re.match(
                        r"^_?(counter|next_id|id_counter|sequence|seq_num|auto_increment)", t.id, re.IGNORECASE
                    ):
                        self._add(node.lineno, "#028", "Replace Sequential IDs", "info",
                                  f"Class `{node.name}` uses sequential ID pattern (`{t.id}`) -- consider UUID",
                                  "architecture")
                        return

    def _check_error_codes(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#051 -- Replace Error Codes with Exceptions."""
        return_ints: set[int] = set()
        total_returns = 0
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value is not None:
                total_returns += 1
                if isinstance(child.value, ast.Constant) and isinstance(child.value.value, int):
                    if isinstance(child.value.value, bool):
                        continue
                    return_ints.add(child.value.value)
                elif isinstance(child.value, ast.UnaryOp) and isinstance(child.value.op, ast.USub):
                    if isinstance(child.value.operand, ast.Constant) and isinstance(child.value.operand.value, int):
                        return_ints.add(-child.value.operand.value)
        if len(return_ints) >= 2 and total_returns >= 2:
            if return_ints.issubset({-1, 0, 1, -2, 2}):
                self._add(node.lineno, "#051", "Replace Error Codes with Exceptions", "warning",
                          f"`{node.name}` returns status codes {sorted(return_ints)} -- use exceptions",
                          "architecture")

    def _check_law_of_demeter(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#054 -- Law of Demeter: chained .attr.attr.attr access."""
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                depth = 1
                current = child.value
                while isinstance(current, ast.Attribute):
                    depth += 1
                    current = current.value
                if depth >= 3 and isinstance(current, ast.Name) and current.id != "self":
                    parts = [child.attr]
                    inner = child.value
                    while isinstance(inner, ast.Attribute):
                        parts.append(inner.attr)
                        inner = inner.value
                    if isinstance(inner, ast.Name):
                        parts.append(inner.id)
                    chain = ".".join(reversed(parts))
                    self._add(child.lineno, "#054", "Law of Demeter", "info",
                              f"Chain `{chain}` ({depth + 1} deep) in `{node.name}` -- introduce a delegate",
                              "architecture")
                    return

    # =======================================================================
    # Hygiene
    # =======================================================================

    def _check_bare_except(self, node: ast.ExceptHandler):
        """#004 -- Remove Unhandled Exceptions."""
        is_bare = node.type is None
        is_broad = (isinstance(node.type, ast.Name) and node.type.id == "Exception")
        body_is_pass = (len(node.body) == 1 and isinstance(node.body[0], ast.Pass))

        if is_bare:
            self._add(node.lineno, "#004", "Remove Unhandled Exceptions", "error",
                      "Bare `except:` -- always catch specific exceptions",
                      "hygiene")
        elif is_broad and body_is_pass:
            self._add(node.lineno, "#004", "Remove Unhandled Exceptions", "warning",
                      "`except Exception: pass` -- silently swallowing all errors",
                      "hygiene")

    def _check_empty_catch(self, node: ast.ExceptHandler):
        """#065 -- Remove Empty Catch Block: except SomeError: pass."""
        # Skip cases already handled by #004 (bare except, except Exception: pass)
        if node.type is None:
            return
        if isinstance(node.type, ast.Name) and node.type.id == "Exception":
            return
        body_is_pass = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
        if body_is_pass and node.type is not None:
            exc_name = ""
            if isinstance(node.type, ast.Name):
                exc_name = node.type.id
            elif isinstance(node.type, ast.Attribute):
                exc_name = node.type.attr
            else:
                exc_name = ast.dump(node.type)
            self._add(node.lineno, "#065", "Remove Empty Catch Block", "warning",
                      f"`except {exc_name}: pass` -- silently swallowing `{exc_name}`",
                      "hygiene")

    def _check_magic_numbers(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#003 -- Extract Constant: magic numbers."""
        return_lines = set()
        default_nodes: set[int] = set()
        for d in node.args.defaults + node.args.kw_defaults:
            if d is not None:
                default_nodes.add(id(d))
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and isinstance(getattr(child, "value", None), ast.Constant):
                return_lines.add(child.lineno)

        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, (int, float)):
                if child.value in MAGIC_NUMBER_WHITELIST:
                    continue
                if id(child) in default_nodes:
                    continue
                if child.lineno in return_lines:
                    continue
                if isinstance(child.value, int) and -10 <= child.value <= 10:
                    continue
                self._add(child.lineno, "#003", "Extract Constant", "info",
                          f"Magic number `{child.value}` -- extract to a named constant",
                          "hygiene")

    def _check_string_concat(self, node: ast.BinOp):
        """#036 -- Replace String Concatenation."""
        if not isinstance(node.op, ast.Add):
            return
        if node.lineno in self._string_concat_lines:
            return
        parts = 0
        current: ast.AST = node
        while isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            parts += 1
            current = current.left
        if parts >= 3:
            self._string_concat_lines.add(node.lineno)
            self._add(node.lineno, "#036", "Replace String Concatenation", "info",
                      "Multiple string concatenations -- consider f-string or triple-quoted string",
                      "hygiene")

    # =======================================================================
    # Python Idioms
    # =======================================================================

    def _check_mutable_default(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#057 -- Replace Mutable Default Arguments."""
        for default in node.args.defaults + node.args.kw_defaults:
            if default is not None and _is_mutable_literal(default):
                self._add(node.lineno, "#057", "Replace Mutable Default Arguments", "error",
                          f"`{node.name}` has mutable default argument -- use `None` sentinel",
                          "idioms")

    def _check_open_without_with(self, node: ast.Call):
        """#058 -- Use Context Managers."""
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            self._open_calls_outside_with.append((node.lineno, "open"))

    def _check_cyclomatic_complexity(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """Cyclomatic Complexity check."""
        cc = _cyclomatic_complexity(node)
        if cc > MAX_CYCLOMATIC_COMPLEXITY:
            self._add(node.lineno, "#CC", "Reduce Cyclomatic Complexity", "warning",
                      f"`{node.name}` has CC={cc} (threshold: {MAX_CYCLOMATIC_COMPLEXITY}) -- split into smaller functions",
                      "functions")

    def _check_index_access(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#062 -- Use Unpacking Instead of Indexing."""
        index_accesses: dict[str, list[int]] = defaultdict(list)
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Subscript)
                and isinstance(child.value, ast.Name)
                and isinstance(child.slice, ast.Constant)
                and isinstance(child.slice.value, int)
            ):
                index_accesses[child.value.id].append(child.slice.value)
        for var_name, indices in index_accesses.items():
            unique = sorted(set(indices))
            if len(unique) >= 3 and unique[:3] == [0, 1, 2]:
                self._add(node.lineno, "#062", "Use Unpacking Instead of Indexing", "info",
                          f"`{var_name}[0]`, `{var_name}[1]`, `{var_name}[2]`... in `{node.name}` -- use unpacking",
                          "idioms")

    def _check_return_none_or_value(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#029 -- Replace NULL with Collection."""
        returns_none = False
        returns_value = False
        for child in ast.walk(node):
            if isinstance(child, ast.Return):
                if child.value is None or _is_none(child.value):
                    returns_none = True
                elif isinstance(child.value, (ast.List, ast.ListComp, ast.GeneratorExp)):
                    returns_value = True
                else:
                    returns_value = True
        if returns_none and returns_value:
            for child in ast.walk(node):
                if (isinstance(child, ast.Return)
                        and child.value is not None
                        and isinstance(child.value, (ast.List, ast.ListComp))):
                    self._add(node.lineno, "#029", "Replace NULL with Collection", "info",
                              f"`{node.name}` returns both None and a list -- always return empty list",
                              "types")
                    return

    def _check_dead_code_after_return(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#021 -- Remove Dead Code."""
        terminal = (ast.Return, ast.Raise, ast.Break, ast.Continue)

        def _check_body(body: list[ast.stmt]):
            for i, stmt in enumerate(body):
                if isinstance(stmt, terminal) and i < len(body) - 1:
                    next_stmt = body[i + 1]
                    self._add(next_stmt.lineno, "#021", "Remove Dead Code", "warning",
                              f"Unreachable code after `{type(stmt).__name__.lower()}` in `{node.name}`",
                              "hygiene")
                    return
                if isinstance(stmt, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                    for attr in ("body", "orelse", "finalbody", "handlers"):
                        sub = getattr(stmt, attr, None)
                        if isinstance(sub, list):
                            if attr == "handlers":
                                for handler in sub:
                                    if isinstance(handler, ast.ExceptHandler):
                                        _check_body(handler.body)
                            else:
                                _check_body(sub)

        _check_body(node.body)

    def _check_input_in_logic(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """#026 -- Replace input() Calls."""
        if node.name in ("main", "__main__", "cli", "repl", "prompt", "interactive"):
            return
        for child in ast.walk(node):
            if (isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == "input"):
                self._add(child.lineno, "#026", "Replace input() Calls", "warning",
                          f"`input()` in `{node.name}` -- inject data via parameters",
                          "functions")
                return

    def _check_dataclass_candidate(self, node: ast.ClassDef):
        """#061 -- Replace Class with Dataclass."""
        method_names = set()
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_names.add(stmt.name)
        if _has_decorator(node, {"dataclass", "dataclasses"}):
            return
        boilerplate = method_names & {"__init__", "__repr__", "__eq__", "__hash__", "__str__"}
        if len(boilerplate) >= 2:
            self._add(node.lineno, "#061", "Replace Class with Dataclass", "info",
                      f"Class `{node.name}` implements {', '.join(sorted(boilerplate))} -- consider @dataclass",
                      "idioms")

    def _check_context_manager_class(self, node: ast.ClassDef):
        """#063 -- Replace with contextlib."""
        method_names = set()
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_names.add(stmt.name)
        if "__enter__" in method_names and "__exit__" in method_names:
            real_methods = {m for m in method_names if not m.startswith("__") or m in ("__init__",)}
            if len(real_methods) <= 2:
                self._add(node.lineno, "#063", "Replace with contextlib", "info",
                          f"Class `{node.name}` implements __enter__/__exit__ -- consider @contextmanager",
                          "idioms")

    # =======================================================================
    # Data collection for cross-file analysis (Tier 2/3)
    # =======================================================================

    def _collect_func_data(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """Collect function signature data for duplicate detection."""
        lines = _lines_of(node)
        if lines < MIN_DUPLICATE_LINES:
            return
        norm = _normalize_ast(node)
        sig_hash = hashlib.md5(norm.encode()).hexdigest()[:HASH_PREFIX_LEN]
        self.file_data.func_signatures.append(
            (self.filepath, node.name, node.lineno, sig_hash, lines)
        )

    def _collect_external_accesses(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """Collect external attribute accesses for feature-envy detection."""
        if not self._class_stack:
            return
        accesses: dict[str, int] = Counter()
        self_accesses = 0
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
                if child.value.id == "self":
                    self_accesses += 1
                elif child.value.id[0].isupper():
                    accesses[child.value.id] += 1
        for cls_name, count in accesses.items():
            if count >= FEATURE_ENVY_THRESHOLD and count > self_accesses:
                self.file_data.method_external_accesses.append(
                    (node.name, node.lineno, self._class_stack[-1].name, {cls_name: count})
                )

    def _collect_defined_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """Track function definitions for shotgun surgery detection."""
        self.file_data.defined_functions.add(node.name)

    def _collect_called_functions(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """Track function calls for shotgun surgery and RFC detection."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    self.file_data.called_functions.add(child.func.id)
                elif isinstance(child.func, ast.Attribute):
                    self.file_data.called_functions.add(child.func.attr)

    def _collect_class_info(self, node: ast.ClassDef):
        """Collect detailed class information for Tier 2/3 analysis."""
        bases = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                bases.append(base.id)
            elif isinstance(base, ast.Attribute):
                bases.append(base.attr)

        self.file_data.class_bases[node.name] = bases
        self.file_data.class_lines[node.name] = node.lineno

        ci = ClassInfo(name=node.name, filepath=self.filepath, line=node.lineno, bases=bases)

        # Check for abstract methods and ABC base
        is_abstract = "ABC" in bases or "ABCMeta" in bases
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ci.method_count += 1
                if not stmt.name.startswith("__"):
                    ci.non_dunder_method_count += 1
                if _has_decorator(stmt, {"abstractmethod"}):
                    ci.abstract_methods.append(stmt.name)
                    is_abstract = True

                # Collect fields accessed by this method
                fields_accessed: set[str] = set()
                for child in ast.walk(stmt):
                    if (isinstance(child, ast.Attribute)
                            and isinstance(child.value, ast.Name)
                            and child.value.id == "self"):
                        fields_accessed.add(child.attr)
                ci.methods_using_fields[stmt.name] = fields_accessed

                # Collect init fields
                if stmt.name == "__init__":
                    for child in ast.walk(stmt):
                        if (isinstance(child, ast.Attribute)
                                and isinstance(child.value, ast.Name)
                                and child.value.id == "self"
                                and isinstance(child.ctx, ast.Store)):
                            ci.all_fields.append(child.attr)
                            ci.field_count += 1

                # Detect delegation methods (body is just return self.x.method(...))
                if len(stmt.body) == 1:
                    s = stmt.body[0]
                    if isinstance(s, ast.Return) and isinstance(s.value, ast.Call):
                        func = s.value.func
                        if (isinstance(func, ast.Attribute)
                                and isinstance(func.value, ast.Attribute)
                                and isinstance(func.value.value, ast.Name)
                                and func.value.value.id == "self"):
                            ci.delegation_count += 1
                    elif isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
                        func = s.value.func
                        if (isinstance(func, ast.Attribute)
                                and isinstance(func.value, ast.Attribute)
                                and isinstance(func.value.value, ast.Name)
                                and func.value.value.id == "self"):
                            ci.delegation_count += 1

        # Collect external class accesses for intimacy/CBO and external method calls for RFC
        ext_accesses: dict[str, int] = Counter()
        ext_method_calls: set[str] = set()
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(stmt):
                    if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
                        if child.value.id != "self" and child.value.id[0:1].isupper():
                            ext_accesses[child.value.id] += 1
                    # Track distinct external method calls: self.x.method() and ClassName.method()
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                        receiver = child.func.value
                        method_name = child.func.attr
                        if isinstance(receiver, ast.Name) and receiver.id != "self":
                            ext_method_calls.add(f"{receiver.id}.{method_name}")
                        elif (isinstance(receiver, ast.Attribute)
                              and isinstance(receiver.value, ast.Name)
                              and receiver.value.id == "self"):
                            ext_method_calls.add(f"self.{receiver.attr}.{method_name}")
        ci.external_class_accesses = dict(ext_accesses)
        ci.external_method_calls = ext_method_calls
        ci.is_abstract = is_abstract

        if is_abstract:
            self.file_data.abstract_classes.add(node.name)

        self.file_data.class_info.append(ci)

    # =======================================================================
    # Visitors
    # =======================================================================

    def visit_ClassDef(self, node: ast.ClassDef):
        if not self._class_stack and not self._func_stack:
            self.file_data.toplevel_defs += 1
            self.file_data.class_names.append(node.name)

        self._class_stack.append(node)
        self._check_singleton(node)
        self._check_sequential_ids(node)
        self._check_dataclass_candidate(node)
        self._check_context_manager_class(node)
        self._check_lazy_class(node)
        self._check_temporary_fields(node)
        self._collect_class_info(node)
        self.generic_visit(node)
        self._class_stack.pop()

        # Post-class checks
        cls_name = node.name
        none_attrs = self._class_attrs.get(cls_name, [])
        if len(none_attrs) >= 2:
            self._add(node.lineno, "#016", "Build With The Essence", "warning",
                      f"`{cls_name}.__init__` sets {len(none_attrs)} attrs to None: "
                      f"{', '.join(none_attrs[:5])} -- require them in constructor",
                      "state")

        bool_attrs = self._class_bool_attrs.get(cls_name, [])
        if len(bool_attrs) >= 3:
            self._add(node.lineno, "#017", "Convert Attributes to Sets", "info",
                      f"`{cls_name}` has {len(bool_attrs)} boolean flags: "
                      f"{', '.join(bool_attrs)} -- consider a roles/tags set",
                      "state")

        method_count = self._class_methods.get(cls_name, 0)
        if method_count > MAX_CLASS_METHODS:
            self._add(node.lineno, "#007", "Extract Class", "info",
                      f"`{cls_name}` has {method_count} methods -- consider splitting",
                      "types")

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._visit_func(node)

    def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        if self._class_stack:
            self._class_methods[self._class_stack[-1].name] += 1
        if not self._class_stack and not self._func_stack:
            self.file_data.toplevel_defs += 1

        self._func_stack.append(node)

        # All function-level checks
        self._check_setters(node)
        self._check_half_built_init(node)
        self._check_bool_flag_attrs(node)
        self._check_public_attrs(node)
        self._check_long_function(node)
        self._check_deep_nesting(node)
        self._check_too_many_params(node)
        self._check_mutable_default(node)
        self._check_excessive_decorators(node)
        self._check_generic_names(node)
        self._check_cqs_violation(node)
        self._check_magic_numbers(node)
        self._check_return_none_or_value(node)
        self._check_dead_code_after_return(node)
        self._check_input_in_logic(node)
        self._check_error_codes(node)
        self._check_law_of_demeter(node)
        self._check_complex_boolean(node)
        self._check_index_access(node)
        self._check_cyclomatic_complexity(node)
        self._check_unused_params(node)
        # Data collection
        self._collect_func_data(node)
        self._collect_external_accesses(node)
        self._collect_defined_function(node)
        self._collect_called_functions(node)

        self.generic_visit(node)
        self._func_stack.pop()

    def visit_If(self, node: ast.If):
        # Skip elif branches -- they are ast.If nodes nested in orelse of the parent If.
        # Only check top-level If nodes to avoid duplicate findings (#014, #068).
        if not self._is_elif(node):
            self._check_isinstance_chain(node)
            self._check_missing_else(node)
        self.generic_visit(node)

    def _is_elif(self, node: ast.If) -> bool:
        """Check if this If node is an elif (nested inside another If's orelse)."""
        # Walk up through the parent chain by checking func/class bodies
        # Since ast doesn't track parents, we check the enclosing scope's body
        scope = self._func_stack[-1] if self._func_stack else None
        if scope is None:
            return False
        for parent in ast.walk(scope):
            if isinstance(parent, ast.If) and parent is not node:
                if len(parent.orelse) == 1 and parent.orelse[0] is node:
                    return True
        return False

    def visit_For(self, node: ast.For):
        self._check_loop_append(node)
        self._check_control_flag(node)
        self.generic_visit(node)

    def visit_While(self, node: ast.While):
        self._check_loop_append(node)
        self._check_control_flag(node)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        self._check_bare_except(node)
        self._check_empty_catch(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        self._check_global_mutable(node)
        self._check_constant_without_final(node)
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        self._check_string_concat(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        self._check_open_without_with(node)
        self.generic_visit(node)

    def visit_Lambda(self, node: ast.Lambda):
        self._check_long_lambda(node)
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp):
        self._check_long_comprehension(node)
        self.generic_visit(node)

    def visit_SetComp(self, node: ast.SetComp):
        self._check_long_comprehension(node)
        self.generic_visit(node)

    def visit_DictComp(self, node: ast.DictComp):
        self._check_long_comprehension(node)
        self.generic_visit(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp):
        self._check_long_comprehension(node)
        self.generic_visit(node)

    def visit_With(self, node: ast.With):
        safe_open_lines: set[int] = set()
        for item in node.items:
            ctx = item.context_expr
            if isinstance(ctx, ast.Call):
                if isinstance(ctx.func, ast.Name) and ctx.func.id == "open":
                    safe_open_lines.add(ctx.lineno)
                elif isinstance(ctx.func, ast.Attribute) and ctx.func.attr == "open":
                    safe_open_lines.add(ctx.lineno)
        # Also clear open() calls wrapped in ExitStack.enter_context(open(...))
        for child in ast.walk(node):
            if (isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Attribute)
                    and child.func.attr == "enter_context"):
                for arg in child.args:
                    if (isinstance(arg, ast.Call)
                            and isinstance(arg.func, ast.Name)
                            and arg.func.id == "open"):
                        safe_open_lines.add(arg.lineno)
        self.generic_visit(node)
        self._open_calls_outside_with = [
            (line, name) for line, name in self._open_calls_outside_with
            if line not in safe_open_lines
        ]

    def finalize(self):
        """Post-traversal checks."""
        for line, name in self._open_calls_outside_with:
            self._add(line, "#058", "Use Context Managers", "warning",
                      f"`{name}()` call without `with` statement -- use context manager",
                      "idioms")


# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------


def scan_file(filepath: Path) -> tuple[list[Finding], FileData | None]:
    """Parse and scan a single Python file."""
    try:
        source = filepath.read_text(encoding="utf-8")
    except (UnicodeDecodeError, PermissionError):
        return [], None
    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError:
        return [], None

    detector = SmellDetector(str(filepath), source)
    detector.visit(tree)
    detector.finalize()
    detector.file_data.imports = _extract_imports(tree)
    return detector.findings, detector.file_data


# ---------------------------------------------------------------------------
# Cross-file analysis (second pass) -- Original patterns
# ---------------------------------------------------------------------------

def _detect_duplicate_functions(all_data: list[FileData]) -> list[Finding]:
    """#013 -- Structurally identical functions via AST-normalized hashing."""
    hash_groups: dict[str, list[tuple[str, str, int, int]]] = defaultdict(list)
    for fd in all_data:
        for filepath, func_name, line, sig_hash, line_count in fd.func_signatures:
            hash_groups[sig_hash].append((filepath, func_name, line, line_count))

    findings: list[Finding] = []
    for group in hash_groups.values():
        if len(group) < 2:
            continue
        if all(lc < MIN_DUPLICATE_LINES for _, _, _, lc in group):
            continue
        first_file, first_name, first_line, _ = group[0]
        others = [f"{Path(fp).name}:{fn}" for fp, fn, _, _ in group[1:]]
        findings.append(Finding(
            file=first_file, line=first_line, pattern="#013",
            name="Remove Duplicated Code", severity="warning",
            message=f"`{first_name}` has structurally identical copies: {', '.join(others)}",
            category="hygiene",
        ))
    return findings


def _detect_cyclic_imports(all_data: list[FileData]) -> list[Finding]:
    """#CYC -- Circular imports via DFS on intra-project import graph."""
    module_map = {fd.filepath: Path(fd.filepath).stem for fd in all_data}
    reverse_map: dict[str, str] = {v: k for k, v in module_map.items()}
    import_graph: dict[str, set[str]] = defaultdict(set)
    for fd in all_data:
        src_module = module_map[fd.filepath]
        for imp in fd.imports:
            if imp in reverse_map:
                import_graph[src_module].add(imp)

    visited: set[str] = set()
    in_stack: set[str] = set()
    cycles: list[tuple[str, str]] = []

    def _dfs(node: str, path: list[str]):
        if node in in_stack:
            cycles.append((path[-1], node))
            return
        if node in visited:
            return
        visited.add(node)
        in_stack.add(node)
        path.append(node)
        for neighbor in import_graph.get(node, set()):
            _dfs(neighbor, path)
        path.pop()
        in_stack.discard(node)

    for module in import_graph:
        visited.clear()
        in_stack.clear()
        _dfs(module, [])

    findings: list[Finding] = []
    reported: set[frozenset[str]] = set()
    for a, b in cycles:
        key = frozenset({a, b})
        if key in reported:
            continue
        reported.add(key)
        findings.append(Finding(
            file=reverse_map.get(a, a), line=1, pattern="#CYC",
            name="Break Cyclic Import", severity="warning",
            message=f"Circular import: `{a}` <-> `{b}` -- extract shared types to break cycle",
            category="architecture",
        ))
    return findings


def _detect_god_modules(all_data: list[FileData]) -> list[Finding]:
    """#GOD -- Modules with too many top-level definitions."""
    return [
        Finding(
            file=fd.filepath, line=1, pattern="#GOD",
            name="Split God Module", severity="warning",
            message=f"Module has {fd.toplevel_defs} top-level definitions "
                    f"(threshold: {MAX_MODULE_TOPLEVEL_DEFS}) -- split into focused modules",
            category="architecture",
        )
        for fd in all_data
        if fd.toplevel_defs > MAX_MODULE_TOPLEVEL_DEFS
    ]


def _detect_feature_envy(all_data: list[FileData]) -> list[Finding]:
    """#FE -- Methods that access external class more than their own."""
    project_classes: set[str] = set()
    for fd in all_data:
        project_classes.update(fd.class_names)

    findings: list[Finding] = []
    for fd in all_data:
        for method_name, line, host_class, external_counts in fd.method_external_accesses:
            for ext_class, count in external_counts.items():
                if ext_class not in project_classes:
                    continue
                findings.append(Finding(
                    file=fd.filepath, line=line, pattern="#FE",
                    name="Move Method (Feature Envy)", severity="info",
                    message=f"`{host_class}.{method_name}` accesses `{ext_class}` "
                            f"{count} times -- consider moving to `{ext_class}`",
                    category="architecture",
                ))
    return findings


# ---------------------------------------------------------------------------
# Cross-file analysis (second pass) -- Tier 2: new patterns
# ---------------------------------------------------------------------------

def _detect_shotgun_surgery(all_data: list[FileData]) -> list[Finding]:
    """#SHO -- Function called from too many different files."""
    defined_in: dict[str, list[str]] = defaultdict(list)
    called_from: dict[str, set[str]] = defaultdict(set)

    for fd in all_data:
        for func_name in fd.defined_functions:
            defined_in[func_name].append(fd.filepath)
        for func_name in fd.called_functions:
            called_from[func_name].add(fd.filepath)

    findings: list[Finding] = []
    for func_name, callers in called_from.items():
        if func_name not in defined_in:
            continue
        # Exclude common names
        if func_name in {"__init__", "__str__", "__repr__", "main", "setup", "run",
                         "get", "set", "update", "delete", "create", "log", "print"}:
            continue
        external_callers = callers - set(defined_in[func_name])
        if len(external_callers) > SHOTGUN_SURGERY_THRESHOLD:
            def_file = defined_in[func_name][0]
            findings.append(Finding(
                file=def_file, line=1, pattern="#SHO",
                name="Shotgun Surgery", severity="info",
                message=f"`{func_name}` is called from {len(external_callers)} different files "
                        f"(threshold: {SHOTGUN_SURGERY_THRESHOLD}) -- changes will cascade widely",
                category="architecture",
            ))
    return findings


def _detect_deep_inheritance(all_data: list[FileData]) -> list[Finding]:
    """#DIT -- Deep inheritance tree."""
    all_bases: dict[str, list[str]] = {}
    all_locations: dict[str, tuple[str, int]] = {}
    for fd in all_data:
        for cls_name, bases in fd.class_bases.items():
            all_bases[cls_name] = bases
            all_locations[cls_name] = (fd.filepath, fd.class_lines.get(cls_name, 1))

    def _depth(cls_name: str, visited: set[str] | None = None) -> int:
        if visited is None:
            visited = set()
        if cls_name in visited or cls_name not in all_bases:
            return 0
        visited.add(cls_name)
        bases = all_bases[cls_name]
        if not bases:
            return 0
        return 1 + max((_depth(b, visited.copy()) for b in bases if b in all_bases), default=0)

    findings: list[Finding] = []
    for cls_name in all_bases:
        d = _depth(cls_name)
        if d > MAX_INHERITANCE_DEPTH:
            filepath, line = all_locations[cls_name]
            findings.append(Finding(
                file=filepath, line=line, pattern="#DIT",
                name="Deep Inheritance Tree", severity="warning",
                message=f"Class `{cls_name}` has inheritance depth {d} "
                        f"(threshold: {MAX_INHERITANCE_DEPTH}) -- favor composition",
                category="types",
            ))
    return findings


def _detect_wide_hierarchy(all_data: list[FileData]) -> list[Finding]:
    """#WHI -- Too many direct subclasses."""
    children: dict[str, list[str]] = defaultdict(list)
    all_locations: dict[str, tuple[str, int]] = {}
    for fd in all_data:
        for cls_name, bases in fd.class_bases.items():
            for base in bases:
                children[base].append(cls_name)
        for cls_name in fd.class_names:
            all_locations[cls_name] = (fd.filepath, fd.class_lines.get(cls_name, 1))

    findings: list[Finding] = []
    for parent, subs in children.items():
        if len(subs) > MAX_DIRECT_SUBCLASSES and parent in all_locations:
            filepath, line = all_locations[parent]
            sub_names = subs[:5]
            findings.append(Finding(
                file=filepath, line=line, pattern="#WHI",
                name="Wide Hierarchy", severity="info",
                message=f"Class `{parent}` has {len(subs)} direct subclasses: "
                        f"{', '.join(sub_names)}{'...' if len(subs) > 5 else ''} -- over-broad abstraction?",
                category="types",
            ))
    return findings


def _detect_inappropriate_intimacy(all_data: list[FileData]) -> list[Finding]:
    """#INT -- Classes that share too many attribute accesses."""
    intimacy: Counter[frozenset[str]] = Counter()
    class_files: dict[str, tuple[str, int]] = {}
    for fd in all_data:
        for ci in fd.class_info:
            class_files[ci.name] = (ci.filepath, ci.line)
            for other_cls, count in ci.external_class_accesses.items():
                if other_cls != ci.name:
                    key = frozenset({ci.name, other_cls})
                    intimacy[key] += count

    findings: list[Finding] = []
    for pair, count in intimacy.items():
        if count > INTIMACY_THRESHOLD:
            a, b = sorted(pair)
            if a in class_files:
                filepath, line = class_files[a]
                findings.append(Finding(
                    file=filepath, line=line, pattern="#INT",
                    name="Inappropriate Intimacy", severity="info",
                    message=f"Classes `{a}` and `{b}` share {count} attribute accesses -- decouple or merge",
                    category="architecture",
                ))
    return findings


def _detect_speculative_generality(all_data: list[FileData]) -> list[Finding]:
    """#SPG -- Abstract classes with no concrete implementations."""
    all_bases_flat: dict[str, list[str]] = {}
    abstract_classes: set[str] = set()
    for fd in all_data:
        abstract_classes.update(fd.abstract_classes)
        for cls_name, bases in fd.class_bases.items():
            all_bases_flat[cls_name] = bases

    concrete_children: Counter[str] = Counter()
    for cls_name, bases in all_bases_flat.items():
        if cls_name not in abstract_classes:
            for base in bases:
                if base in abstract_classes:
                    concrete_children[base] += 1

    findings: list[Finding] = []
    for abc_cls in abstract_classes:
        if concrete_children[abc_cls] == 0:
            for fd in all_data:
                if abc_cls in fd.class_names:
                    findings.append(Finding(
                        file=fd.filepath, line=fd.class_lines.get(abc_cls, 1), pattern="#SPG",
                        name="Remove Speculative Generality", severity="info",
                        message=f"Abstract class `{abc_cls}` has no concrete implementations -- YAGNI?",
                        category="architecture",
                    ))
                    break
    return findings


def _detect_unstable_dependency(all_data: list[FileData]) -> list[Finding]:
    """#UDE -- Module depends on a more unstable module (Robert Martin's I metric)."""
    module_map = {fd.filepath: Path(fd.filepath).stem for fd in all_data}
    reverse_map: dict[str, str] = {v: k for k, v in module_map.items()}

    outgoing: dict[str, set[str]] = defaultdict(set)
    incoming: dict[str, set[str]] = defaultdict(set)
    for fd in all_data:
        src = module_map[fd.filepath]
        for imp in fd.imports:
            if imp in reverse_map:
                outgoing[src].add(imp)
                incoming[imp].add(src)

    instability: dict[str, float] = {}
    for module in module_map.values():
        ce = len(outgoing.get(module, set()))
        ca = len(incoming.get(module, set()))
        total = ca + ce
        instability[module] = ce / total if total > 0 else 0.0

    findings: list[Finding] = []
    for module in module_map.values():
        my_i = instability[module]
        for dep in outgoing.get(module, set()):
            dep_i = instability.get(dep, 0.0)
            if dep_i > my_i and dep_i > 0.7:
                filepath = reverse_map[module]
                findings.append(Finding(
                    file=filepath, line=1, pattern="#UDE",
                    name="Unstable Dependency", severity="info",
                    message=f"Module `{module}` (I={my_i:.2f}) depends on unstable `{dep}` (I={dep_i:.2f})",
                    category="architecture",
                ))
    return findings


# ---------------------------------------------------------------------------
# Cross-file analysis (second pass) -- Tier 3: OO metrics
# ---------------------------------------------------------------------------

def _detect_low_cohesion(all_data: list[FileData]) -> list[Finding]:
    """#LCOM -- Lack of Cohesion of Methods."""
    findings: list[Finding] = []
    for fd in all_data:
        for ci in fd.class_info:
            if ci.method_count < 3 or ci.field_count < 2:
                continue
            methods_fields = ci.methods_using_fields
            all_fields = set(ci.all_fields)
            if not all_fields or not methods_fields:
                continue
            # Exclude __init__ from cohesion calc (it initializes all fields)
            method_set = {m: f for m, f in methods_fields.items() if m != "__init__"}
            if not method_set:
                continue
            total_usage = sum(len(fields & all_fields) for fields in method_set.values())
            max_possible = len(method_set) * len(all_fields)
            if max_possible == 0:
                continue
            cohesion = total_usage / max_possible
            lcom = 1.0 - cohesion
            if lcom > MAX_LCOM:
                findings.append(Finding(
                    file=ci.filepath, line=ci.line, pattern="#LCOM",
                    name="Low Class Cohesion", severity="warning",
                    message=f"Class `{ci.name}` has LCOM={lcom:.2f} "
                            f"(threshold: {MAX_LCOM}) -- consider splitting",
                    category="metrics",
                ))
    return findings


def _detect_high_coupling(all_data: list[FileData]) -> list[Finding]:
    """#CBO -- Coupling Between Objects."""
    findings: list[Finding] = []
    for fd in all_data:
        for ci in fd.class_info:
            coupled_classes = len(ci.external_class_accesses)
            if coupled_classes > MAX_CBO:
                findings.append(Finding(
                    file=ci.filepath, line=ci.line, pattern="#CBO",
                    name="High Coupling Between Objects", severity="warning",
                    message=f"Class `{ci.name}` is coupled to {coupled_classes} other classes "
                            f"(threshold: {MAX_CBO})",
                    category="metrics",
                ))
    return findings


def _detect_fan_out(all_data: list[FileData]) -> list[Finding]:
    """#FIO -- Excessive module fan-out (outgoing dependencies)."""
    module_map = {fd.filepath: Path(fd.filepath).stem for fd in all_data}
    reverse_map: dict[str, str] = {v: k for k, v in module_map.items()}

    findings: list[Finding] = []
    for fd in all_data:
        src = module_map[fd.filepath]
        outgoing = {imp for imp in fd.imports if imp in reverse_map}
        if len(outgoing) > MAX_FANOUT:
            findings.append(Finding(
                file=fd.filepath, line=1, pattern="#FIO",
                name="Excessive Fan-Out", severity="info",
                message=f"Module `{src}` has {len(outgoing)} outgoing dependencies "
                        f"(threshold: {MAX_FANOUT}) -- too many dependencies",
                category="metrics",
            ))
    return findings


def _detect_high_rfc(all_data: list[FileData]) -> list[Finding]:
    """#RFC -- Response for a Class (own methods + directly called external methods)."""
    findings: list[Finding] = []
    for fd in all_data:
        for ci in fd.class_info:
            own_methods = ci.method_count
            external_calls = len(ci.external_method_calls)
            rfc = own_methods + external_calls
            if rfc > MAX_RFC:
                findings.append(Finding(
                    file=ci.filepath, line=ci.line, pattern="#RFC",
                    name="High Response for Class", severity="info",
                    message=f"Class `{ci.name}` has RFC={rfc} "
                            f"({own_methods} methods + {external_calls} external calls) "
                            f"(threshold: {MAX_RFC})",
                    category="metrics",
                ))
    return findings


def _detect_middle_man(all_data: list[FileData]) -> list[Finding]:
    """#MID -- Class where most methods just delegate to another object."""
    findings: list[Finding] = []
    for fd in all_data:
        for ci in fd.class_info:
            if ci.non_dunder_method_count < 3:
                continue
            ratio = ci.delegation_count / ci.non_dunder_method_count
            if ratio > MIDDLE_MAN_RATIO:
                findings.append(Finding(
                    file=ci.filepath, line=ci.line, pattern="#MID",
                    name="Remove Middle Man", severity="info",
                    message=f"Class `{ci.name}` delegates {ci.delegation_count}/{ci.non_dunder_method_count} "
                            f"methods ({ratio:.0%}) -- consider removing the middleman",
                    category="types",
                ))
    return findings


# ---------------------------------------------------------------------------
# Cross-file analysis dispatcher
# ---------------------------------------------------------------------------

def cross_file_analysis(all_data: list[FileData]) -> list[Finding]:
    """Analyze patterns across files: all cross-file and metric checks."""
    findings: list[Finding] = []
    # Original patterns
    findings.extend(_detect_duplicate_functions(all_data))
    findings.extend(_detect_cyclic_imports(all_data))
    findings.extend(_detect_god_modules(all_data))
    findings.extend(_detect_feature_envy(all_data))
    # Tier 2: cross-file patterns
    findings.extend(_detect_shotgun_surgery(all_data))
    findings.extend(_detect_deep_inheritance(all_data))
    findings.extend(_detect_wide_hierarchy(all_data))
    findings.extend(_detect_inappropriate_intimacy(all_data))
    findings.extend(_detect_speculative_generality(all_data))
    findings.extend(_detect_unstable_dependency(all_data))
    # Tier 3: OO metrics
    findings.extend(_detect_low_cohesion(all_data))
    findings.extend(_detect_high_coupling(all_data))
    findings.extend(_detect_fan_out(all_data))
    findings.extend(_detect_high_rfc(all_data))
    findings.extend(_detect_middle_man(all_data))
    return findings


def scan_path(target: Path) -> list[Finding]:
    """Scan a file or directory recursively. Two-pass: per-file then cross-file."""
    all_findings: list[Finding] = []
    all_file_data: list[FileData] = []

    if target.is_file():
        if target.suffix == ".py":
            findings, fd = scan_file(target)
            all_findings.extend(findings)
            if fd:
                all_file_data.append(fd)
    elif target.is_dir():
        for py_file in sorted(target.rglob("*.py")):
            parts = py_file.parts
            if any(p in {".venv", "venv", "__pycache__", ".tox", ".eggs", "node_modules", ".git"} for p in parts):
                continue
            findings, fd = scan_file(py_file)
            all_findings.extend(findings)
            if fd:
                all_file_data.append(fd)

    if len(all_file_data) > 1:
        all_findings.extend(cross_file_analysis(all_file_data))
    elif len(all_file_data) == 1:
        # Single-file scan: still compute per-class metrics (LCOM, CBO, RFC, MID)
        all_findings.extend(_detect_low_cohesion(all_file_data))
        all_findings.extend(_detect_high_coupling(all_file_data))
        all_findings.extend(_detect_high_rfc(all_file_data))
        all_findings.extend(_detect_middle_man(all_file_data))

    return all_findings


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

SEVERITY_COLORS: Final = {
    "error": "\033[91m",
    "warning": "\033[93m",
    "info": "\033[96m",
}
RESET: Final = "\033[0m"
BOLD: Final = "\033[1m"


def _print_summary(filtered: list[Finding]):
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in filtered:
        by_file[f.file].append(f)

    counts = Counter(f.severity for f in filtered)
    pattern_counts = Counter(f.pattern for f in filtered)

    print(f"\n{BOLD}{'=' * SEPARATOR_WIDTH}")
    print(f" Python Smell Detector -- {len(filtered)} findings")
    print(f"{'=' * SEPARATOR_WIDTH}{RESET}")
    print(f"  {SEVERITY_COLORS['error']}errors: {counts.get('error', 0)}{RESET}  "
          f"{SEVERITY_COLORS['warning']}warnings: {counts.get('warning', 0)}{RESET}  "
          f"{SEVERITY_COLORS['info']}info: {counts.get('info', 0)}{RESET}")
    print()

    for filepath, file_findings in sorted(by_file.items()):
        print(f"{BOLD}{filepath}{RESET}")
        for f in sorted(file_findings, key=lambda x: x.line):
            color = SEVERITY_COLORS.get(f.severity, "")
            sev = f.severity.upper()[:4]
            print(f"  {color}{sev}{RESET} L{f.line:<5} {f.pattern} {f.name}")
            print(f"         {f.message}")
        print()

    print(f"{BOLD}Top patterns:{RESET}")
    for pattern, count in pattern_counts.most_common(10):
        matching = next((f for f in filtered if f.pattern == pattern), None)
        name = matching.name if matching else ""
        print(f"  {pattern} {name}: {count}")
    print()


def print_findings(findings: list[Finding], use_json: bool = False, min_severity: str = "info"):
    min_rank = SEVERITY_ORDER.get(min_severity, 0)
    filtered = [f for f in findings if f.severity_rank >= min_rank]

    if use_json:
        print(json.dumps([asdict(f) for f in filtered], indent=2))
    elif not filtered:
        print(f"{BOLD}No code smells found.{RESET}")
    else:
        _print_summary(filtered)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_HELP_TEXT: Final = textwrap.dedent("""\
    Usage: detect_smells.py <path> [options]

    Scan Python files for code smells mapped to the 82-pattern refactoring catalog.

    Detects 55 patterns programmatically:
      - 40 per-file (AST analysis)
      - 10 cross-file (import graph, duplicate detection, inheritance)
      - 5 OO metrics (LCOM, CBO, fan-out, RFC, middle man)

    Options:
      --json              Output as JSON
      --min-severity SEV  Filter: info | warning | error (default: info)
      -h, --help          Show this help

    Examples:
      detect_smells.py src/
      detect_smells.py myfile.py --json
      detect_smells.py src/ --min-severity warning
""")


def _parse_args(argv: list[str]) -> tuple[Path, bool, str]:
    args = list(argv)
    if not args or "--help" in args or "-h" in args:
        print(_HELP_TEXT)
        sys.exit(0)

    use_json = "--json" in args
    if use_json:
        args.remove("--json")

    min_severity = "info"
    if "--min-severity" in args:
        idx = args.index("--min-severity")
        if idx + 1 < len(args):
            min_severity = args[idx + 1]
            if min_severity not in SEVERITY_ORDER:
                print(f"Error: invalid severity '{min_severity}' -- must be one of: info, warning, error",
                      file=sys.stderr)
                sys.exit(1)
            args = args[:idx] + args[idx + 2:]
        else:
            print("Error: --min-severity requires a value (info|warning|error)", file=sys.stderr)
            sys.exit(1)

    target = Path(args[0]).resolve()
    if not target.exists():
        print(f"Error: {target} does not exist", file=sys.stderr)
        sys.exit(1)

    return target, use_json, min_severity


def main():
    target, use_json, min_severity = _parse_args(sys.argv[1:])
    findings = scan_path(target)
    print_findings(findings, use_json=use_json, min_severity=min_severity)
    has_errors = any(f.severity == "error" for f in findings)
    sys.exit(1 if has_errors else 0)


if __name__ == "__main__":
    main()
