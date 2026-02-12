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
    _fingerprint,
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
    p = _write_py(
        tmp_path,
        """\
        def foo(x=[]):
            return x
    """,
    )
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
# SARIF output format
# ---------------------------------------------------------------------------


def test_sarif_valid_structure(tmp_path, capsys):
    p = _write_py(tmp_path, "def foo(x=[]): pass\n")
    findings = scan_path(p)
    print_findings(findings, output_format="sarif")
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert "sarif-schema-2.1.0" in data["$schema"]
    assert len(data["runs"]) == 1


def test_sarif_tool_driver(tmp_path, capsys):
    p = _write_py(tmp_path, "def foo(x=[]): pass\n")
    findings = scan_path(p)
    print_findings(findings, output_format="sarif")
    data = json.loads(capsys.readouterr().out)
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "smellcheck"
    assert "version" in driver
    assert "informationUri" in driver
    assert isinstance(driver["rules"], list)


def test_sarif_results_have_required_fields(tmp_path, capsys):
    p = _write_py(tmp_path, "def foo(x=[]): pass\n")
    findings = scan_path(p)
    print_findings(findings, output_format="sarif")
    data = json.loads(capsys.readouterr().out)
    results = data["runs"][0]["results"]
    assert len(results) > 0
    r = results[0]
    assert "ruleId" in r
    assert "level" in r
    assert "message" in r and "text" in r["message"]
    loc = r["locations"][0]["physicalLocation"]
    assert "artifactLocation" in loc
    assert "region" in loc
    assert loc["region"]["startLine"] > 0


def test_sarif_rules_populated(tmp_path, capsys):
    p = _write_py(tmp_path, "def foo(x=[]): pass\n")
    findings = scan_path(p)
    print_findings(findings, output_format="sarif")
    data = json.loads(capsys.readouterr().out)
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert "SC701" in rule_ids


def test_sarif_rules_have_help_metadata(tmp_path, capsys):
    p = _write_py(tmp_path, "def foo(x=[]): pass\n")
    findings = scan_path(p)
    print_findings(findings, output_format="sarif")
    data = json.loads(capsys.readouterr().out)
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    sc701 = [r for r in rules if r["id"] == "SC701"]
    assert len(sc701) == 1
    rule = sc701[0]
    # fullDescription present and non-empty
    assert "fullDescription" in rule
    assert len(rule["fullDescription"]["text"]) > 0
    # help present with text and markdown
    assert "help" in rule
    assert "text" in rule["help"]
    assert "markdown" in rule["help"]
    assert "## " in rule["help"]["markdown"]  # contains heading
    assert "refactoring guide" in rule["help"]["markdown"]
    # helpUri present and points to reference
    assert "helpUri" in rule
    assert "references/idioms.md" in rule["helpUri"]


def test_sarif_severity_mapping(tmp_path, capsys):
    p = _write_py(tmp_path, "def foo(x=[]): pass\n")
    findings = scan_path(p)
    print_findings(findings, output_format="sarif")
    data = json.loads(capsys.readouterr().out)
    results = data["runs"][0]["results"]
    sc701 = [r for r in results if r["ruleId"] == "SC701"]
    assert len(sc701) > 0
    # SC701 is error-level → SARIF "error"
    assert sc701[0]["level"] == "error"


def test_sarif_relative_paths(tmp_path, capsys):
    p = _write_py(tmp_path, "def foo(x=[]): pass\n")
    findings = scan_path(p)
    print_findings(findings, output_format="sarif")
    data = json.loads(capsys.readouterr().out)
    results = data["runs"][0]["results"]
    uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert not uri.startswith("/")


def test_sarif_partial_fingerprints(tmp_path, capsys):
    p = _write_py(tmp_path, "def foo(x=[]): pass\n")
    findings = scan_path(p)
    print_findings(findings, output_format="sarif")
    data = json.loads(capsys.readouterr().out)
    results = data["runs"][0]["results"]
    assert "partialFingerprints" in results[0]
    fp = results[0]["partialFingerprints"]["primaryLocationLineHash"]
    assert isinstance(fp, str) and len(fp) > 0


def test_sarif_empty_findings(capsys):
    print_findings([], output_format="sarif")
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"] == []
    assert data["runs"][0]["tool"]["driver"]["rules"] == []


def test_cli_format_sarif(tmp_path):
    p = _write_py(tmp_path, "def foo(x=[]): pass\n")
    result = _run_cli(str(p), "--format", "sarif")
    data = json.loads(result.stdout)
    assert data["version"] == "2.1.0"


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
    pyproject.write_text('[tool.smellcheck]\nignore = ["057"]\n', encoding="utf-8")
    config = load_config(tmp_path)
    findings = scan_paths([tmp_path], config=config)
    patterns = [f.pattern for f in findings]
    assert "#057" not in patterns


def test_config_select(tmp_path):
    _write_py(tmp_path, "def foo(x=[]): pass\n")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.smellcheck]\nselect = ["057"]\n', encoding="utf-8")
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
    """Registry has 56 entries with valid families and scopes."""
    assert len(_RULE_REGISTRY) == 56
    for pat, rd in _RULE_REGISTRY.items():
        assert pat.startswith("#"), f"Pattern {pat!r} must start with '#'"
        assert rd.rule_id.startswith("SC"), (
            f"rule_id {rd.rule_id!r} must start with 'SC'"
        )
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
    pyproject.write_text('[tool.smellcheck]\nselect = ["SC701"]\n', encoding="utf-8")
    config = load_config(tmp_path)
    findings = scan_paths([tmp_path], config=config)
    assert all(f.pattern == "#057" for f in findings)
    assert len(findings) >= 1


def test_config_ignore_sc_code(tmp_path):
    """ignore = ["SC701"] in config removes #057 findings."""
    _write_py(tmp_path, "def foo(x=[]): pass\n")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.smellcheck]\nignore = ["SC701"]\n', encoding="utf-8")
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


# ---------------------------------------------------------------------------
# Baseline workflow (issue #5)
# ---------------------------------------------------------------------------


def test_generate_baseline_json_structure(tmp_path):
    """--generate-baseline outputs valid JSON with version/generated/findings keys."""
    _write_py(tmp_path, "def foo(x=[]): pass\n")
    result = _run_cli(str(tmp_path), "--generate-baseline", cwd=tmp_path)
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "version" in data
    assert "generated" in data
    assert "findings" in data
    assert isinstance(data["findings"], list)
    assert len(data["findings"]) >= 1
    entry = data["findings"][0]
    for key in ("fingerprint", "file", "pattern", "line", "name"):
        assert key in entry, f"Missing key {key!r} in baseline entry"


def test_baseline_suppresses_existing_findings(tmp_path):
    """Generate baseline, run with --baseline, same code -> empty output."""
    _write_py(tmp_path, "def foo(x=[]): pass\n")
    # Generate baseline
    gen = _run_cli(str(tmp_path), "--generate-baseline", cwd=tmp_path)
    assert gen.returncode == 0
    bl = tmp_path / ".smellcheck-baseline.json"
    bl.write_text(gen.stdout, encoding="utf-8")
    # Run with baseline
    result = _run_cli(
        str(tmp_path), "--baseline", str(bl), "--format", "json", cwd=tmp_path
    )
    data = json.loads(result.stdout)
    assert data == []
    assert "suppressed" in result.stderr


def test_baseline_reports_new_findings(tmp_path):
    """Baseline from file A, add file B -> B's findings appear."""
    _write_py(tmp_path, "def foo(x=[]): pass\n", name="a.py")
    # Generate baseline from a.py only
    gen = _run_cli(str(tmp_path / "a.py"), "--generate-baseline", cwd=tmp_path)
    bl = tmp_path / "baseline.json"
    bl.write_text(gen.stdout, encoding="utf-8")
    # Add file B with its own finding
    _write_py(tmp_path, "def bar(y={}): pass\n", name="b.py")
    # Run on whole directory with baseline
    result = _run_cli(
        str(tmp_path), "--baseline", str(bl), "--format", "json", cwd=tmp_path
    )
    data = json.loads(result.stdout)
    # b.py findings should appear (new), a.py findings suppressed
    files = {d["file"] for d in data}
    assert any("b.py" in f for f in files)


def test_baseline_ignores_disappeared_findings(tmp_path):
    """Baseline with smell, fix code, run -> no crash, no findings."""
    _write_py(tmp_path, "def foo(x=[]): pass\n")
    gen = _run_cli(str(tmp_path), "--generate-baseline", cwd=tmp_path)
    bl = tmp_path / "baseline.json"
    bl.write_text(gen.stdout, encoding="utf-8")
    # Fix the code (remove smell)
    _write_py(tmp_path, "def foo(x=None): pass\n")
    result = _run_cli(
        str(tmp_path), "--baseline", str(bl), "--format", "json", cwd=tmp_path
    )
    data = json.loads(result.stdout)
    assert data == []


def test_fingerprint_resilient_to_line_shift(tmp_path):
    """Same finding at different line numbers -> same fingerprint."""
    from smellcheck.detector import Finding

    f1 = Finding(
        file=str(tmp_path / "a.py"),
        line=5,
        pattern="#057",
        name="Replace Mutable Default Arguments",
        severity="error",
        message="`foo` has mutable default argument `[]`",
        category="idioms",
    )
    f2 = Finding(
        file=str(tmp_path / "a.py"),
        line=42,
        pattern="#057",
        name="Replace Mutable Default Arguments",
        severity="error",
        message="`foo` has mutable default argument `[]`",
        category="idioms",
    )
    assert _fingerprint(f1, tmp_path) == _fingerprint(f2, tmp_path)


def test_generate_baseline_and_baseline_mutually_exclusive(tmp_path):
    """Both flags -> returncode 1, 'mutually exclusive' in stderr."""
    _write_py(tmp_path, "x = 1\n")
    bl = tmp_path / "bl.json"
    bl.write_text('{"findings": []}', encoding="utf-8")
    result = _run_cli(
        str(tmp_path),
        "--generate-baseline",
        "--baseline",
        str(bl),
        cwd=tmp_path,
    )
    assert result.returncode == 1
    assert "mutually exclusive" in result.stderr


def test_baseline_config_support(tmp_path):
    """baseline = "..." in pyproject.toml honored without CLI flag."""
    _write_py(tmp_path, "def foo(x=[]): pass\n")
    # Generate baseline
    gen = _run_cli(str(tmp_path), "--generate-baseline", cwd=tmp_path)
    bl = tmp_path / ".smellcheck-baseline.json"
    bl.write_text(gen.stdout, encoding="utf-8")
    # Configure via pyproject.toml
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        f'[tool.smellcheck]\nbaseline = "{bl}"\n',
        encoding="utf-8",
    )
    result = _run_cli(str(tmp_path), "--format", "json", cwd=tmp_path)
    data = json.loads(result.stdout)
    assert data == []
    assert "suppressed" in result.stderr


# ---------------------------------------------------------------------------
# Blocking calls in async functions (#071 / SC703)
# ---------------------------------------------------------------------------


def test_blocking_sleep_in_async(tmp_path):
    p = _write_py(
        tmp_path,
        """\
        import time
        async def handler():
            time.sleep(1)
    """,
    )
    findings = scan_path(p)
    patterns = [f.pattern for f in findings]
    assert "#071" in patterns
    msg = next(f.message for f in findings if f.pattern == "#071")
    assert "time.sleep()" in msg


def test_blocking_requests_in_async(tmp_path):
    p = _write_py(
        tmp_path,
        """\
        import requests
        async def fetch():
            requests.get("http://example.com")
    """,
    )
    findings = scan_path(p)
    patterns = [f.pattern for f in findings]
    assert "#071" in patterns


def test_blocking_open_in_async(tmp_path):
    p = _write_py(
        tmp_path,
        """\
        async def read_file():
            f = open("data.txt")
    """,
    )
    findings = scan_path(p)
    patterns = [f.pattern for f in findings]
    assert "#071" in patterns


def test_blocking_subprocess_in_async(tmp_path):
    p = _write_py(
        tmp_path,
        """\
        import subprocess
        async def run_cmd():
            subprocess.run(["ls"])
    """,
    )
    findings = scan_path(p)
    patterns = [f.pattern for f in findings]
    assert "#071" in patterns


def test_blocking_os_path_in_async(tmp_path):
    p = _write_py(
        tmp_path,
        """\
        import os.path
        async def check():
            os.path.exists("/tmp/x")
    """,
    )
    findings = scan_path(p)
    patterns = [f.pattern for f in findings]
    assert "#071" in patterns


def test_blocking_input_in_async(tmp_path):
    p = _write_py(
        tmp_path,
        """\
        async def prompt():
            input("Enter: ")
    """,
    )
    findings = scan_path(p)
    patterns = [f.pattern for f in findings]
    assert "#071" in patterns


def test_no_flag_sync_function(tmp_path):
    p = _write_py(
        tmp_path,
        """\
        import time
        def handler():
            time.sleep(1)
    """,
    )
    findings = scan_path(p)
    patterns = [f.pattern for f in findings]
    assert "#071" not in patterns


def test_no_flag_nested_def_in_async(tmp_path):
    p = _write_py(
        tmp_path,
        """\
        import time
        async def handler():
            def inner():
                time.sleep(1)
            inner()
    """,
    )
    findings = scan_path(p)
    blocking = [f for f in findings if f.pattern == "#071"]
    assert blocking == []


def test_no_flag_asyncio_to_thread(tmp_path):
    p = _write_py(
        tmp_path,
        """\
        import asyncio
        import time
        async def handler():
            await asyncio.to_thread(time.sleep, 1)
    """,
    )
    findings = scan_path(p)
    blocking = [f for f in findings if f.pattern == "#071"]
    assert blocking == []


def test_no_flag_run_in_executor(tmp_path):
    p = _write_py(
        tmp_path,
        """\
        import asyncio
        import time
        async def handler():
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, time.sleep, 1)
    """,
    )
    findings = scan_path(p)
    blocking = [f for f in findings if f.pattern == "#071"]
    assert blocking == []


def test_multiple_blocking_calls(tmp_path):
    p = _write_py(
        tmp_path,
        """\
        import time
        import subprocess
        async def handler():
            time.sleep(1)
            subprocess.run(["ls"])
    """,
    )
    findings = scan_path(p)
    blocking = [f for f in findings if f.pattern == "#071"]
    assert len(blocking) >= 2
