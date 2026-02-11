"""Smoke tests and CLI tests for smellcheck."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

from smellcheck import __version__
from smellcheck.detector import (
    _RULE_REGISTRY,
    _VALID_FAMILIES,
    _VALID_SCOPES,
    _parse_args,
    _resolve_code,
    load_config,
    print_findings,
    scan_path,
    scan_paths,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_py(tmp_path: Path, code: str, name: str = "sample.py") -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(code), encoding="utf-8")
    return p


def _run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "smellcheck", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
    )


# ---------------------------------------------------------------------------
# Basic import / version
# ---------------------------------------------------------------------------


def test_version_is_string():
    assert isinstance(__version__, str)
    assert len(__version__) > 0


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def test_empty_file_no_findings(tmp_path):
    p = _write_py(tmp_path, "")
    findings = scan_path(p)
    assert findings == []


def test_mutable_default_detected(tmp_path):
    p = _write_py(tmp_path, """\
        def foo(x=[]):
            return x
    """)
    findings = scan_path(p)
    patterns = [f.pattern for f in findings]
    assert "#057" in patterns


def test_scan_directory(tmp_path):
    _write_py(tmp_path, "x = 1\n", name="a.py")
    _write_py(tmp_path, "y = 2\n", name="b.py")
    findings = scan_path(tmp_path)
    # No crashes, may or may not have findings
    assert isinstance(findings, list)


def test_multiple_paths(tmp_path):
    p1 = _write_py(tmp_path, "def foo(x=[]): pass\n", name="a.py")
    p2 = _write_py(tmp_path, "def bar(y={}): pass\n", name="b.py")
    findings = scan_paths([p1, p2])
    patterns = [f.pattern for f in findings]
    assert patterns.count("#057") >= 2


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


def test_parse_args_format_github(tmp_path):
    p = _write_py(tmp_path, "x = 1\n")
    paths, fmt, sev, fail_on, select, ignore, scope = _parse_args(
        [str(p), "--format", "github"]
    )
    assert fmt == "github"
    assert paths == [p.resolve()]


def test_parse_args_fail_on(tmp_path):
    p = _write_py(tmp_path, "x = 1\n")
    paths, fmt, sev, fail_on, select, ignore, scope = _parse_args(
        [str(p), "--fail-on", "warning"]
    )
    assert fail_on == "warning"


def test_parse_args_multiple_paths(tmp_path):
    p1 = _write_py(tmp_path, "x = 1\n", name="a.py")
    p2 = _write_py(tmp_path, "y = 2\n", name="b.py")
    paths, *_ = _parse_args([str(p1), str(p2)])
    assert len(paths) == 2


def test_json_deprecated_alias(tmp_path):
    p = _write_py(tmp_path, "x = 1\n")
    paths, fmt, *_ = _parse_args([str(p), "--json"])
    assert fmt == "json"


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------


def test_json_output_format(tmp_path, capsys):
    p = _write_py(tmp_path, "def foo(x=[]): pass\n")
    findings = scan_path(p)
    print_findings(findings, output_format="json")
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list)
    assert any(d["pattern"] == "#057" for d in data)


def test_github_output_format(tmp_path, capsys):
    p = _write_py(tmp_path, "def foo(x=[]): pass\n")
    findings = scan_path(p)
    print_findings(findings, output_format="github")
    out = capsys.readouterr().out
    assert "::error " in out or "::warning " in out or "::notice " in out
    assert "file=" in out
    assert "line=" in out


# ---------------------------------------------------------------------------
# Inline suppression (# noqa)
# ---------------------------------------------------------------------------


def test_noqa_suppression(tmp_path):
    p = _write_py(tmp_path, "def foo(x=[]):  # noqa: SC057\n    pass\n")
    findings = scan_paths([p])
    patterns = [f.pattern for f in findings]
    assert "#057" not in patterns


def test_noqa_all(tmp_path):
    p = _write_py(tmp_path, "def foo(x=[]):  # noqa\n    pass\n")
    findings = scan_paths([p])
    # All findings on line 1 should be suppressed
    line1_findings = [f for f in findings if f.line == 1]
    assert line1_findings == []


# ---------------------------------------------------------------------------
# Config support
# ---------------------------------------------------------------------------


def test_config_ignore(tmp_path):
    _write_py(tmp_path, "def foo(x=[]): pass\n")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.smellcheck]\nignore = ["057"]\n', encoding="utf-8"
    )
    config = load_config(tmp_path)
    findings = scan_paths([tmp_path], config=config)
    patterns = [f.pattern for f in findings]
    assert "#057" not in patterns


def test_config_select(tmp_path):
    _write_py(tmp_path, "def foo(x=[]): pass\n")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.smellcheck]\nselect = ["057"]\n', encoding="utf-8"
    )
    config = load_config(tmp_path)
    findings = scan_paths([tmp_path], config=config)
    # Only #057 findings should remain
    assert all(f.pattern == "#057" for f in findings)
    assert len(findings) >= 1


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


def test_fail_on_exit_code(tmp_path):
    _write_py(tmp_path, "def foo(x=[]): pass\n")  # #057 is severity=error
    # --fail-on error (default) should exit 1
    result = _run_cli(str(tmp_path), "--fail-on", "error")
    assert result.returncode == 1

    # --fail-on with severity above all findings should exit 0
    # Write a file that only produces info-level findings
    clean = _write_py(tmp_path, "result = 42\n", name="clean.py")
    result2 = _run_cli(str(clean), "--fail-on", "error")
    assert result2.returncode == 0


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_version():
    result = _run_cli("--version")
    assert result.returncode == 0
    assert "smellcheck" in result.stdout


def test_cli_help():
    result = _run_cli("--help")
    assert result.returncode == 0
    assert "--format" in result.stdout
    assert "--fail-on" in result.stdout
    assert "--scope" in result.stdout


# ---------------------------------------------------------------------------
# Unified SC code naming system (issue #4)
# ---------------------------------------------------------------------------


def test_rule_registry_complete():
    """Registry has 55 entries with valid families and scopes."""
    assert len(_RULE_REGISTRY) == 55
    for pat, rd in _RULE_REGISTRY.items():
        assert pat.startswith("#"), f"Pattern {pat!r} must start with '#'"
        assert rd.rule_id.startswith("SC"), f"rule_id {rd.rule_id!r} must start with 'SC'"
        assert rd.family in _VALID_FAMILIES, f"Invalid family {rd.family!r} for {pat}"
        assert rd.scope in _VALID_SCOPES, f"Invalid scope {rd.scope!r} for {pat}"
        assert rd.default_severity in {"info", "warning", "error"}, (
            f"Invalid severity {rd.default_severity!r} for {pat}"
        )


def test_rule_id_populated(tmp_path):
    """Mutable default triggers #057 with rule_id SC701 and scope file."""
    p = _write_py(tmp_path, "def foo(x=[]):\n    return x\n")
    findings = scan_path(p)
    f057 = [f for f in findings if f.pattern == "#057"]
    assert len(f057) >= 1
    assert f057[0].rule_id == "SC701"
    assert f057[0].scope == "file"


def test_resolve_code_formats():
    """_resolve_code handles SC701, 057, #057, SC057, CC."""
    assert _resolve_code("SC701") == {"#057"}
    assert _resolve_code("057") == {"#057"}
    assert _resolve_code("#057") == {"#057"}
    assert _resolve_code("SC057") == {"#057"}
    assert _resolve_code("CC") == {"#CC"}
    assert _resolve_code("SC210") == {"#CC"}
    assert _resolve_code("LCOM") == {"#LCOM"}
    assert _resolve_code("NONEXISTENT") == set()


def test_noqa_with_sc_rule_id(tmp_path):
    """``# noqa: SC701`` suppresses #057 findings."""
    p = _write_py(tmp_path, "def foo(x=[]):  # noqa: SC701\n    pass\n")
    findings = scan_paths([p])
    patterns = [f.pattern for f in findings]
    assert "#057" not in patterns


def test_config_select_sc_code(tmp_path):
    """select = ["SC701"] in config keeps only #057 findings."""
    _write_py(tmp_path, "def foo(x=[]): pass\n")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.smellcheck]\nselect = ["SC701"]\n', encoding="utf-8"
    )
    config = load_config(tmp_path)
    findings = scan_paths([tmp_path], config=config)
    assert all(f.pattern == "#057" for f in findings)
    assert len(findings) >= 1


def test_config_ignore_sc_code(tmp_path):
    """ignore = ["SC701"] in config removes #057 findings."""
    _write_py(tmp_path, "def foo(x=[]): pass\n")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.smellcheck]\nignore = ["SC701"]\n', encoding="utf-8"
    )
    config = load_config(tmp_path)
    findings = scan_paths([tmp_path], config=config)
    patterns = [f.pattern for f in findings]
    assert "#057" not in patterns


def test_scope_filter_cli(tmp_path):
    """--scope file excludes cross-file and metric findings."""
    p = _write_py(tmp_path, "def foo(x=[]): pass\n")
    result = _run_cli(str(p), "--scope", "file", "--format", "json")
    data = json.loads(result.stdout)
    # All findings should have scope == "file"
    assert all(d.get("scope") == "file" for d in data)


def test_json_includes_rule_id(tmp_path):
    """JSON output includes rule_id and scope fields."""
    p = _write_py(tmp_path, "def foo(x=[]): pass\n")
    findings = scan_path(p)
    print_findings(findings, output_format="json")
    # Verify through dataclass fields directly
    f057 = [f for f in findings if f.pattern == "#057"]
    assert len(f057) >= 1
    from dataclasses import asdict
    d = asdict(f057[0])
    assert "rule_id" in d
    assert "scope" in d
    assert d["rule_id"] == "SC701"
    assert d["scope"] == "file"
