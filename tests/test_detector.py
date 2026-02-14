"""Smoke tests and CLI tests for smellcheck."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

from smellcheck import __version__
from smellcheck.detector import (
    _DEFAULT_CACHE_DIR,
    _RULE_DESCRIPTIONS,
    _RULE_EXAMPLES,
    _RULE_REGISTRY,
    _VALID_FAMILIES,
    _VALID_SCOPES,
    _cache_key,
    _clear_cache,
    _config_hash,
    _deserialize_file_data,
    _deserialize_finding,
    _fingerprint,
    _is_suppressed,
    _parse_args,
    _parse_block_directives,
    _read_cache,
    _resolve_code,
    _serialize_file_data,
    _serialize_finding,
    _write_cache,
    FileData,
    Finding,
    load_config,
    print_findings,
    scan_file,
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
    assert "SC701" in patterns


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
    assert patterns.count("SC701") >= 2


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
    assert any(d["pattern"] == "SC701" for d in data)


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
    p = _write_py(tmp_path, "def foo(x=[]):  # noqa: SC701\n    pass\n")
    findings = scan_paths([p])
    patterns = [f.pattern for f in findings]
    assert "SC701" not in patterns


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
    pyproject.write_text('[tool.smellcheck]\nignore = ["SC701"]\n', encoding="utf-8")
    config = load_config(tmp_path)
    findings = scan_paths([tmp_path], config=config)
    patterns = [f.pattern for f in findings]
    assert "SC701" not in patterns


def test_config_select(tmp_path):
    _write_py(tmp_path, "def foo(x=[]): pass\n")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.smellcheck]\nselect = ["SC701"]\n', encoding="utf-8")
    config = load_config(tmp_path)
    findings = scan_paths([tmp_path], config=config)
    assert all(f.pattern == "SC701" for f in findings)
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
    for key, rd in _RULE_REGISTRY.items():
        assert key.startswith("SC"), f"Key {key!r} must start with 'SC'"
        assert key == rd.rule_id, f"Key {key!r} must match rule_id {rd.rule_id!r}"
        assert rd.family in _VALID_FAMILIES, f"Invalid family {rd.family!r} for {key}"
        assert rd.scope in _VALID_SCOPES, f"Invalid scope {rd.scope!r} for {key}"
        assert rd.default_severity in {"info", "warning", "error"}, (
            f"Invalid severity {rd.default_severity!r} for {key}"
        )


def test_rule_id_populated(tmp_path):
    """Mutable default triggers SC701 with scope file."""
    p = _write_py(tmp_path, "def foo(x=[]):\n    return x\n")
    findings = scan_path(p)
    f701 = [f for f in findings if f.pattern == "SC701"]
    assert len(f701) >= 1
    assert f701[0].scope == "file"


def test_resolve_code_formats():
    """_resolve_code handles SC codes only."""
    assert _resolve_code("SC701") == {"SC701"}
    assert _resolve_code("SC210") == {"SC210"}
    assert _resolve_code("SC801") == {"SC801"}
    assert _resolve_code("SC503") == {"SC503"}
    assert _resolve_code("sc701") == {"SC701"}  # case-insensitive
    assert _resolve_code("NONEXISTENT") == set()
    assert _resolve_code("057") == set()  # legacy bare numbers no longer resolve
    assert _resolve_code("#057") == set()  # legacy #-prefix no longer resolves
    assert _resolve_code("CC") == set()  # legacy alpha codes no longer resolve


def test_noqa_with_sc_rule_id(tmp_path):
    """``# noqa: SC701`` suppresses SC701 findings."""
    p = _write_py(tmp_path, "def foo(x=[]):  # noqa: SC701\n    pass\n")
    findings = scan_paths([p])
    patterns = [f.pattern for f in findings]
    assert "SC701" not in patterns


def test_config_select_sc_code(tmp_path):
    """select = ["SC701"] in config keeps only SC701 findings."""
    _write_py(tmp_path, "def foo(x=[]): pass\n")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.smellcheck]\nselect = ["SC701"]\n', encoding="utf-8")
    config = load_config(tmp_path)
    findings = scan_paths([tmp_path], config=config)
    assert all(f.pattern == "SC701" for f in findings)
    assert len(findings) >= 1


def test_config_ignore_sc_code(tmp_path):
    """ignore = ["SC701"] in config removes SC701 findings."""
    _write_py(tmp_path, "def foo(x=[]): pass\n")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.smellcheck]\nignore = ["SC701"]\n', encoding="utf-8")
    config = load_config(tmp_path)
    findings = scan_paths([tmp_path], config=config)
    patterns = [f.pattern for f in findings]
    assert "SC701" not in patterns


def test_scope_filter_cli(tmp_path):
    """--scope file excludes cross-file and metric findings."""
    p = _write_py(tmp_path, "def foo(x=[]): pass\n")
    result = _run_cli(str(p), "--scope", "file", "--format", "json")
    data = json.loads(result.stdout)
    # All findings should have scope == "file"
    assert all(d.get("scope") == "file" for d in data)


def test_json_includes_scope(tmp_path):
    """JSON output includes scope field; pattern is the SC code."""
    p = _write_py(tmp_path, "def foo(x=[]): pass\n")
    findings = scan_path(p)
    print_findings(findings, output_format="json")
    f701 = [f for f in findings if f.pattern == "SC701"]
    assert len(f701) >= 1
    from dataclasses import asdict

    d = asdict(f701[0])
    assert "scope" in d
    assert d["pattern"] == "SC701"
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
        pattern="SC701",
        name="Replace Mutable Default Arguments",
        severity="error",
        message="`foo` has mutable default argument `[]`",
        category="idioms",
    )
    f2 = Finding(
        file=str(tmp_path / "a.py"),
        line=42,
        pattern="SC701",
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
    assert "SC703" in patterns
    msg = next(f.message for f in findings if f.pattern == "SC703")
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
    assert "SC703" in patterns


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
    assert "SC703" in patterns


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
    assert "SC703" in patterns


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
    assert "SC703" in patterns


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
    assert "SC703" in patterns


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
    assert "SC703" not in patterns


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
    blocking = [f for f in findings if f.pattern == "SC703"]
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
    blocking = [f for f in findings if f.pattern == "SC703"]
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
    blocking = [f for f in findings if f.pattern == "SC703"]
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
    blocking = [f for f in findings if f.pattern == "SC703"]
    assert len(blocking) >= 2


def test_offloaded_and_standalone_blocking_call(tmp_path):
    """Offloading one call should not suppress a separate standalone blocking call."""
    p = _write_py(
        tmp_path,
        """\
        import asyncio
        import time
        async def handler():
            await asyncio.to_thread(time.sleep, 1)
            time.sleep(5)  # standalone -- should still be flagged
    """,
    )
    findings = scan_path(p)
    blocking = [f for f in findings if f.pattern == "SC703"]
    assert len(blocking) == 1
    assert "time.sleep" in blocking[0].message


# ---------------------------------------------------------------------------
# --explain
# ---------------------------------------------------------------------------


def test_explain_single_rule():
    r = _run_cli("--explain", "SC701")
    assert r.returncode == 0
    assert "SC701" in r.stdout
    assert "Mutable Default" in r.stdout
    assert "Before:" in r.stdout
    assert "After:" in r.stdout
    assert "# noqa: SC701" in r.stdout


def test_explain_single_rule_lowercase():
    r = _run_cli("--explain", "sc701")
    assert r.returncode == 0
    assert "SC701" in r.stdout


def test_explain_family():
    r = _run_cli("--explain", "SC4")
    assert r.returncode == 0
    assert "Control Flow" in r.stdout
    assert "SC401" in r.stdout
    assert "SC407" in r.stdout


def test_explain_family_xx_suffix():
    """SC4xx form should work the same as SC4."""
    r = _run_cli("--explain", "SC4xx")
    assert r.returncode == 0
    assert "Control Flow" in r.stdout
    assert "SC401" in r.stdout


def test_explain_all():
    r = _run_cli("--explain", "all")
    assert r.returncode == 0
    for family in ["State", "Functions", "Types", "Control", "Architecture", "Hygiene", "Idioms", "Metrics"]:
        assert family in r.stdout


def test_explain_bare():
    """--explain with no argument lists all rules."""
    r = _run_cli("--explain")
    assert r.returncode == 0
    assert "SC101" in r.stdout
    assert "SC805" in r.stdout


def test_explain_invalid_code():
    r = _run_cli("--explain", "SC999")
    assert r.returncode != 0
    out = r.stdout + r.stderr
    assert "unknown" in out.lower() or "no rule" in out.lower()


def test_explain_all_rules_have_descriptions():
    """Every rule in the registry must have a description."""
    for code in _RULE_REGISTRY:
        assert code in _RULE_DESCRIPTIONS, f"{code} missing from _RULE_DESCRIPTIONS"


def test_explain_all_rules_have_examples_entry():
    """Every rule in the registry must have an entry in _RULE_EXAMPLES."""
    for code in _RULE_REGISTRY:
        assert code in _RULE_EXAMPLES, f"{code} missing from _RULE_EXAMPLES"


# ---------------------------------------------------------------------------
# File-level caching
# ---------------------------------------------------------------------------


def test_cache_hit_skips_reanalysis(tmp_path):
    """Second scan of unchanged file should use cache and produce same results."""
    p = _write_py(tmp_path, """\
        def process(items=[]):
            pass
    """)
    cache_dir = tmp_path / ".smellcheck-cache"

    # First scan — populates cache
    findings1 = scan_paths([tmp_path], cache_dir=cache_dir, use_cache=True)
    assert cache_dir.is_dir()
    cache_files = list(cache_dir.glob("*.json"))
    assert len(cache_files) == 1

    # Second scan — should hit cache, same results
    findings2 = scan_paths([tmp_path], cache_dir=cache_dir, use_cache=True)
    assert len(findings2) == len(findings1)
    for f1, f2 in zip(findings1, findings2):
        assert f1.pattern == f2.pattern
        assert f1.line == f2.line
        assert f1.message == f2.message


def test_cache_miss_on_file_change(tmp_path):
    """Modifying a file should invalidate its cache entry."""
    p = _write_py(tmp_path, """\
        def process(items=[]):
            pass
    """)
    cache_dir = tmp_path / ".smellcheck-cache"

    # First scan
    findings1 = scan_paths([tmp_path], cache_dir=cache_dir, use_cache=True)
    assert any(f.pattern == "SC701" for f in findings1)

    # Modify file to remove the smell
    p.write_text("def process(items=None):\n    pass\n", encoding="utf-8")

    # Second scan — cache miss, new results
    findings2 = scan_paths([tmp_path], cache_dir=cache_dir, use_cache=True)
    assert not any(f.pattern == "SC701" for f in findings2)

    # Should now have 2 cache files (old stale + new)
    cache_files = list(cache_dir.glob("*.json"))
    assert len(cache_files) == 2


def test_no_cache_flag_disables_caching(tmp_path):
    """use_cache=False should not create a cache directory."""
    _write_py(tmp_path, """\
        x = 1
    """)
    cache_dir = tmp_path / ".smellcheck-cache"

    scan_paths([tmp_path], cache_dir=cache_dir, use_cache=False)
    assert not cache_dir.exists()


def test_clear_cache(tmp_path):
    """_clear_cache should remove all .json files from cache dir."""
    cache_dir = tmp_path / ".smellcheck-cache"
    cache_dir.mkdir()
    (cache_dir / "abc123.json").write_text("{}", encoding="utf-8")
    (cache_dir / "def456.json").write_text("{}", encoding="utf-8")

    removed = _clear_cache(cache_dir)
    assert removed == 2
    assert list(cache_dir.glob("*.json")) == []


def test_cache_invalidated_by_config_change(tmp_path):
    """Different config should produce different cache keys."""
    p = _write_py(tmp_path, """\
        def process(items=[]):
            pass
    """)
    source = p.read_text(encoding="utf-8")

    key1 = _cache_key(source, _config_hash(None), "0.3.2")
    key2 = _cache_key(source, _config_hash({"select": ["SC701"]}), "0.3.2")
    assert key1 != key2


def test_cache_invalidated_by_version_change(tmp_path):
    """Different smellcheck version should produce different cache keys."""
    p = _write_py(tmp_path, """\
        x = 1
    """)
    source = p.read_text(encoding="utf-8")
    cfg = _config_hash(None)

    key1 = _cache_key(source, cfg, "0.3.1")
    key2 = _cache_key(source, cfg, "0.3.2")
    assert key1 != key2


def test_finding_serialization_roundtrip():
    """Finding should survive JSON serialization/deserialization."""
    f = Finding(
        file="test.py",
        line=42,
        pattern="SC701",
        name="Mutable Default",
        severity="error",
        message="mutable default arg",
        category="idioms",
        scope="file",
    )
    d = _serialize_finding(f)
    f2 = _deserialize_finding(d)
    assert f == f2


def test_file_data_serialization_roundtrip(tmp_path):
    """FileData should survive serialization via scan_file."""
    p = _write_py(tmp_path, """\
        class Foo:
            def __init__(self):
                self.x = 1
            def bar(self):
                return self.x
    """)
    findings, fd = scan_file(p)
    assert fd is not None

    serialized = _serialize_file_data(fd)
    restored = _deserialize_file_data(serialized)

    assert restored.filepath == fd.filepath
    assert restored.toplevel_defs == fd.toplevel_defs
    assert restored.class_names == fd.class_names
    assert restored.total_lines == fd.total_lines


def test_cache_cross_file_still_runs(tmp_path):
    """Cross-file analysis must still run even when per-file results are cached."""
    # Create two files that import each other (cyclic import)
    (tmp_path / "a.py").write_text(
        "import b\ndef fa(): pass\n", encoding="utf-8"
    )
    (tmp_path / "b.py").write_text(
        "import a\ndef fb(): pass\n", encoding="utf-8"
    )
    cache_dir = tmp_path / ".smellcheck-cache"

    # First scan — populates cache + cross-file
    findings1 = scan_paths([tmp_path], cache_dir=cache_dir, use_cache=True)
    cyclic1 = [f for f in findings1 if f.pattern == "SC503"]
    assert len(cyclic1) > 0, "Expected cyclic import findings"

    # Second scan — per-file cached, cross-file must still run
    findings2 = scan_paths([tmp_path], cache_dir=cache_dir, use_cache=True)
    cyclic2 = [f for f in findings2 if f.pattern == "SC503"]

    assert len(cyclic2) == len(cyclic1)


def test_cli_no_cache(tmp_path):
    """--no-cache flag should work via CLI."""
    _write_py(tmp_path, "x = 1\n")
    result = _run_cli(str(tmp_path), "--no-cache")
    assert result.returncode == 0
    assert not (tmp_path / _DEFAULT_CACHE_DIR).exists()


def test_cli_cache_dir(tmp_path):
    """--cache-dir should use the specified directory."""
    _write_py(tmp_path, "x = 1\n")
    custom_cache = tmp_path / "my-cache"
    result = _run_cli(str(tmp_path), "--cache-dir", str(custom_cache))
    assert result.returncode == 0
    assert custom_cache.is_dir()


def test_cli_clear_cache(tmp_path):
    """--clear-cache should remove cache entries and exit."""
    cache_dir = tmp_path / _DEFAULT_CACHE_DIR
    cache_dir.mkdir()
    (cache_dir / "test.json").write_text("{}", encoding="utf-8")

    result = _run_cli("--clear-cache", "--cache-dir", str(cache_dir))
    assert result.returncode == 0
    assert "Cleared 1" in result.stdout
    assert list(cache_dir.glob("*.json")) == []


def test_corrupted_cache_treated_as_miss(tmp_path):
    """Corrupted cache file should be silently ignored (cache miss)."""
    p = _write_py(tmp_path, """\
        def process(items=[]):
            pass
    """)
    cache_dir = tmp_path / ".smellcheck-cache"
    cache_dir.mkdir()

    # Write a corrupted cache file
    (cache_dir / "fake.json").write_text("NOT JSON", encoding="utf-8")

    # Scan should work fine, treating corrupted entry as miss
    findings = scan_paths([tmp_path], cache_dir=cache_dir, use_cache=True)
    assert any(f.pattern == "SC701" for f in findings)


# ---------------------------------------------------------------------------
# Block-level suppression tests
# ---------------------------------------------------------------------------


def test_block_disable_enable(tmp_path):
    """# smellcheck: disable SC701 ... # smellcheck: enable SC701"""
    _write_py(tmp_path, """\
        # smellcheck: disable SC701
        def foo(x=[]):
            return x
        # smellcheck: enable SC701

        def bar(y=[]):
            return y
    """)
    findings = scan_paths([tmp_path], use_cache=False)
    sc701 = [f for f in findings if f.pattern == "SC701"]
    # foo should be suppressed, bar should NOT be suppressed
    assert len(sc701) == 1
    assert "bar" in sc701[0].message or sc701[0].line > 5


def test_block_disable_multiple_codes(tmp_path):
    """# smellcheck: disable SC701, SC206 suppresses both codes."""
    _write_py(tmp_path, """\
        # smellcheck: disable SC701, SC206
        def foo(a, b, c, d, e, f, g=[]):
            return a
        # smellcheck: enable SC701, SC206

        def bar(a, b, c, d, e, f, g=[]):
            return a
    """)
    findings = scan_paths([tmp_path], use_cache=False)
    # foo should have no SC701 or SC206; bar should have both
    suppressed_region = [f for f in findings if f.line <= 4]
    unsuppressed_region = [f for f in findings if f.line > 5]
    assert not any(f.pattern in ("SC701", "SC206") for f in suppressed_region)
    assert any(f.pattern == "SC701" for f in unsuppressed_region)
    assert any(f.pattern == "SC206" for f in unsuppressed_region)


def test_block_enable_partial(tmp_path):
    """enable SC701 re-enables only SC701; SC206 stays suppressed."""
    _write_py(tmp_path, """\
        # smellcheck: disable SC701, SC206
        def foo(a, b, c, d, e, f, g=[]):
            return a
        # smellcheck: enable SC701

        def bar(a, b, c, d, e, f, h=[]):
            return a
        # smellcheck: enable SC206
    """)
    findings = scan_paths([tmp_path], use_cache=False)
    bar_findings = [f for f in findings if f.line >= 6 and f.line <= 8]
    # bar should have SC701 (re-enabled) but NOT SC206 (still disabled)
    assert any(f.pattern == "SC701" for f in bar_findings)
    assert not any(f.pattern == "SC206" for f in bar_findings)


def test_block_disable_all_enable_all(tmp_path):
    """# smellcheck: disable-all suppresses everything."""
    _write_py(tmp_path, """\
        # smellcheck: disable-all
        def foo(x=[]):
            return x
        # smellcheck: enable-all

        def bar(y=[]):
            return y
    """)
    findings = scan_paths([tmp_path], use_cache=False)
    # foo region should have nothing; bar should have SC701
    suppressed = [f for f in findings if f.line <= 4]
    assert len(suppressed) == 0
    assert any(f.pattern == "SC701" for f in findings if f.line > 5)


def test_block_disable_file_specific_codes(tmp_path):
    """# smellcheck: disable-file SC701 suppresses SC701 for entire file."""
    _write_py(tmp_path, """\
        # smellcheck: disable-file SC701

        def foo(x=[]):
            return x

        def bar(y=[]):
            return y
    """)
    findings = scan_paths([tmp_path], use_cache=False)
    assert not any(f.pattern == "SC701" for f in findings)


def test_block_disable_file_all(tmp_path):
    """# smellcheck: disable-file (no codes) suppresses everything."""
    _write_py(tmp_path, """\
        # smellcheck: disable-file

        def foo(x=[]):
            return x
        MAGIC = 42
    """)
    findings = scan_paths([tmp_path], use_cache=False)
    assert len(findings) == 0


def test_block_unterminated_disable(tmp_path):
    """Unterminated disable applies to end of file."""
    _write_py(tmp_path, """\
        # smellcheck: disable SC701
        def foo(x=[]):
            return x

        def bar(y=[]):
            return y
    """)
    findings = scan_paths([tmp_path], use_cache=False)
    # Both foo and bar SC701 should be suppressed (no enable before EOF)
    assert not any(f.pattern == "SC701" for f in findings)


def test_block_noqa_still_works_with_block(tmp_path):
    """Per-line # noqa still works alongside block directives."""
    _write_py(tmp_path, """\
        def foo(x=[]):  # noqa: SC701
            return x

        def bar(y=[]):
            return y
    """)
    findings = scan_paths([tmp_path], use_cache=False)
    sc701 = [f for f in findings if f.pattern == "SC701"]
    # foo suppressed by noqa, bar not suppressed
    assert len(sc701) == 1
    assert sc701[0].line > 3


def test_block_unknown_codes_ignored(tmp_path):
    """Unknown SC codes in directives don't crash."""
    _write_py(tmp_path, """\
        # smellcheck: disable SC999
        def foo(x=[]):
            return x
        # smellcheck: enable SC999
    """)
    findings = scan_paths([tmp_path], use_cache=False)
    # SC999 doesn't exist, so SC701 should still fire
    assert any(f.pattern == "SC701" for f in findings)


def test_block_case_insensitive(tmp_path):
    """Directive codes are case-insensitive."""
    _write_py(tmp_path, """\
        # smellcheck: disable sc701
        def foo(x=[]):
            return x
        # smellcheck: enable sc701
    """)
    findings = scan_paths([tmp_path], use_cache=False)
    assert not any(f.pattern == "SC701" for f in findings)


def test_block_whitespace_tolerance(tmp_path):
    """Various whitespace patterns in directives are accepted."""
    _write_py(tmp_path, """\
        #smellcheck: disable SC701
        def foo(x=[]):
            return x
        #  smellcheck:  enable  SC701

        # smellcheck:disable SC701
        def bar(y=[]):
            return y
        # smellcheck:enable SC701
    """)
    findings = scan_paths([tmp_path], use_cache=False)
    assert not any(f.pattern == "SC701" for f in findings)


def test_block_cross_file_not_affected(tmp_path):
    """Block directives do NOT suppress cross-file findings."""
    # Create two files that import each other (cyclic import = SC503)
    a = tmp_path / "mod_a.py"
    b = tmp_path / "mod_b.py"
    a.write_text(
        "# smellcheck: disable SC503\nimport mod_b\n# smellcheck: enable SC503\n",
        encoding="utf-8",
    )
    b.write_text("import mod_a\n", encoding="utf-8")
    findings = scan_paths([tmp_path], use_cache=False)
    sc503 = [f for f in findings if f.pattern == "SC503"]
    # SC503 is cross-file scope — block directives should NOT suppress it
    assert len(sc503) > 0


def test_block_disable_file_does_suppress_cross_file(tmp_path):
    """disable-file DOES suppress cross-file findings (file-level intent)."""
    a = tmp_path / "mod_a.py"
    b = tmp_path / "mod_b.py"
    a.write_text(
        "# smellcheck: disable-file SC503\nimport mod_b\n",
        encoding="utf-8",
    )
    b.write_text("import mod_a\n", encoding="utf-8")
    findings = scan_paths([tmp_path], use_cache=False)
    # SC503 reported on mod_a should be suppressed; mod_b's finding may remain
    sc503_a = [f for f in findings if f.pattern == "SC503" and "mod_a" in f.file]
    assert len(sc503_a) == 0


def test_parse_block_directives_unit():
    """Unit test for _parse_block_directives with known lines."""
    lines = [
        "# smellcheck: disable SC701",      # line 1
        "def foo(x=[]):",                     # line 2
        "    return x",                       # line 3
        "# smellcheck: enable SC701",        # line 4
        "def bar(y=[]):",                     # line 5
    ]
    block_map, daf, fdc = _parse_block_directives(lines)
    assert not daf
    assert len(fdc) == 0
    assert "SC701" in block_map
    ranges = block_map["SC701"]
    assert len(ranges) == 1
    start, end = ranges[0]
    assert start == 1 and end == 4
    # Line 2 is in range [1, 4)
    assert start <= 2 < end
    # Line 5 is NOT in range
    assert not (start <= 5 < end)


def test_parse_block_directives_disable_all():
    """Unit test for disable-all / enable-all."""
    lines = [
        "# smellcheck: disable-all",  # line 1
        "x = 42",                      # line 2
        "# smellcheck: enable-all",   # line 3
        "y = 99",                      # line 4
    ]
    block_map, daf, fdc = _parse_block_directives(lines)
    assert not daf
    assert "*" in block_map
    start, end = block_map["*"][0]
    assert start == 1 and end == 3


def test_parse_block_directives_disable_file():
    """Unit test for disable-file."""
    lines = [
        "# smellcheck: disable-file SC301, SC305",
        "class Foo:",
        "    pass",
    ]
    block_map, daf, fdc = _parse_block_directives(lines)
    assert not daf
    assert "SC301" in fdc
    assert "SC305" in fdc


def test_parse_block_directives_disable_file_all():
    """Unit test for disable-file with no codes (suppress all)."""
    lines = [
        "# smellcheck: disable-file",
        "class Foo:",
        "    pass",
    ]
    block_map, daf, fdc = _parse_block_directives(lines)
    assert daf is True
    assert len(fdc) == 0


def test_parse_block_directives_enable_all_without_disable_all():
    """enable-all without prior disable-all is a no-op."""
    lines = [
        "# smellcheck: disable SC701",       # line 1
        "def foo(x=[]):",                      # line 2
        "# smellcheck: enable-all",           # line 3 — no disable-all active
        "def bar(y=[]):",                      # line 4
    ]
    block_map, daf, fdc = _parse_block_directives(lines)
    assert not daf
    # SC701 range should extend to EOF (unterminated, not closed by enable-all)
    assert "SC701" in block_map
    start, end = block_map["SC701"][0]
    assert start == 1 and end == 5  # total + 1


def test_parse_block_directives_duplicate_disable():
    """Double disable of same code is idempotent."""
    lines = [
        "# smellcheck: disable SC701",  # line 1
        "# smellcheck: disable SC701",  # line 2 — redundant, ignored
        "def foo(x=[]):",                # line 3
        "# smellcheck: enable SC701",   # line 4
    ]
    block_map, daf, fdc = _parse_block_directives(lines)
    assert "SC701" in block_map
    # Only one range (first disable to the enable)
    assert len(block_map["SC701"]) == 1
    start, end = block_map["SC701"][0]
    assert start == 1 and end == 4


def test_block_disable_all_with_trailing_codes(tmp_path):
    """disable-all with trailing codes ignores the codes (suppresses all)."""
    _write_py(tmp_path, """\
        # smellcheck: disable-all SC701
        def foo(x=[]):
            return x
        MAGIC = 42
        # smellcheck: enable-all
    """)
    findings = scan_paths([tmp_path], use_cache=False)
    suppressed = [f for f in findings if f.line <= 5]
    assert len(suppressed) == 0


def test_explain_mentions_block_suppression(tmp_path):
    """--explain output includes block suppression syntax."""
    result = _run_cli("--explain", "SC701")
    assert result.returncode == 0
    assert "smellcheck: disable" in result.stdout
    assert "smellcheck: enable" in result.stdout
    assert "smellcheck: disable-file" in result.stdout
