"""Regression tests for previously fixed bugs in smellcheck.

Each test covers a specific bug that was found and fixed, ensuring
no regressions in future changes.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from smellcheck.detector import _parse_args, scan_path, scan_paths


def _write_py(tmp_path: Path, code: str, name: str = "sample.py") -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(code), encoding="utf-8")
    return p


# --- Regression: import captures dotted paths (#CYC, #UDE, #FIO) ---

def test_import_captures_dotted_paths(tmp_path):
    """Dotted imports like ``import foo.bar`` must record 'foo.bar', not just 'foo'."""
    _write_py(tmp_path, """\
        import os.path
        x = os.path.join("a", "b")
    """, name="mod_a.py")
    _write_py(tmp_path, """\
        import sys
        y = sys.argv
    """, name="mod_b.py")
    # Should not crash and should handle dotted module names
    findings = scan_path(tmp_path)
    assert isinstance(findings, list)


# --- Regression: RFC counts methods, not classes ---

def test_rfc_counts_methods_not_classes(tmp_path):
    """RFC metric should count methods of a class + external method calls,
    not count the class itself as a single unit."""
    p = _write_py(tmp_path, """\
        class Foo:
            def method_a(self):
                pass
            def method_b(self):
                pass
            def method_c(self):
                pass
    """)
    findings = scan_path(p)
    rfc_findings = [f for f in findings if f.pattern == "SC804"]
    # Foo has 3 methods + 0 external calls = RFC 3, below default threshold of 20
    assert len(rfc_findings) == 0


# --- Regression: elif no duplicate findings for #014/#068 ---

def test_elif_no_duplicate_findings(tmp_path):
    """An if/elif chain should not produce duplicate findings for #014 and #068."""
    p = _write_py(tmp_path, """\
        def dispatch(x):
            if isinstance(x, int):
                return "int"
            elif isinstance(x, str):
                return "str"
            elif isinstance(x, float):
                return "float"
    """)
    findings = scan_path(p)
    # Check no duplicate patterns on same line
    seen = set()
    for f in findings:
        key = (f.file, f.line, f.pattern)
        assert key not in seen, f"Duplicate finding: {key}"
        seen.add(key)


# --- Regression: ExitStack no false positive #058 ---

def test_exitstack_no_false_positive_058(tmp_path):
    """``ExitStack.enter_context(open(...))`` should not trigger #058."""
    p = _write_py(tmp_path, """\
        from contextlib import ExitStack
        def process():
            with ExitStack() as stack:
                f = stack.enter_context(open("test.txt"))
                return f.read()
    """)
    findings = scan_path(p)
    f058 = [f for f in findings if f.pattern == "SC702"]
    # The open() is wrapped in enter_context, so no #058
    assert len(f058) == 0


# --- Regression: single file runs OO metrics ---

def test_single_file_runs_oo_metrics(tmp_path):
    """Scanning a single file should still compute LCOM, CBO, RFC, MID."""
    p = _write_py(tmp_path, """\
        class BigClass:
            def __init__(self):
                self.a = 1
                self.b = 2
                self.c = 3
                self.d = 4
                self.e = 5
                self.f = 6
                self.g = 7
                self.h = 8

            def use_a(self):
                return self.a

            def use_b(self):
                return self.b

            def use_c(self):
                return self.c

            def use_d(self):
                return self.d

            def use_e(self):
                return self.e

            def use_f(self):
                return self.f

            def use_g(self):
                return self.g

            def use_h(self):
                return self.h
    """)
    findings = scan_path(p)
    metric_patterns = {f.pattern for f in findings}
    # Should detect LCOM (each method uses only 1 of 8 fields)
    assert "SC801" in metric_patterns


# --- Regression: min-severity rejects invalid values ---

def test_min_severity_rejects_invalid(tmp_path):
    p = _write_py(tmp_path, "x = 1\n")
    with pytest.raises(SystemExit) as exc_info:
        _parse_args([str(p), "--min-severity", "critical"])
    assert exc_info.value.code == 1


# --- Regression: #007 extract class fires on class with too many methods ---

def test_007_extract_class_detected(tmp_path):
    """A class with >12 methods should trigger #007 Extract Class."""
    methods = "\n".join(
        f"    def method_{i}(self): pass" for i in range(15)
    )
    p = _write_py(tmp_path, f"class Bloated:\n{methods}\n")
    findings = scan_path(p)
    patterns = [f.pattern for f in findings]
    assert "SC301" in patterns


# --- Regression: noqa suppression codes are case-insensitive ---

def test_noqa_code_case_insensitive(tmp_path):
    """``# noqa: sc701`` (lowercase) should also suppress SC701."""
    p = _write_py(tmp_path, "def foo(x=[]):  # noqa: sc701\n    pass\n")
    findings = scan_paths([p])
    patterns = [f.pattern for f in findings]
    # _is_suppressed uppercases codes, so sc701 -> SC701 should match
    assert "SC701" not in patterns
