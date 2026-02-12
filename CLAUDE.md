# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install (editable)
pip install -e .

# Run tests
pytest tests/ -v
pytest tests/test_detector.py::test_name -v   # single test

# Self-check (CI runs this too)
smellcheck src/smellcheck/ --min-severity warning

# CLI usage
smellcheck path/ [--format text|json|github] [--min-severity info|warning|error]
smellcheck path/ --fail-on warning
smellcheck path/ --generate-baseline > .smellcheck-baseline.json
smellcheck path/ --baseline .smellcheck-baseline.json
```

Build system is hatchling. No linter config beyond self-check — the project has zero external dependencies by design.

## Architecture

**Single-file core**: `src/smellcheck/detector.py` (~3000 lines) is intentionally monolithic. Do not split it.

The detector has four layers that run in sequence:

1. **Per-file AST analysis** — `SmellDetector(ast.NodeVisitor)` walks each file. ~35 `_check_*` methods called from `visit_*` hooks. Each emits `Finding` objects via `self._add()`.

2. **Cross-file analysis** — `cross_file_analysis(all_data)` runs after all files are visited. Uses `FileData` collected per-file to detect cyclic imports, god modules, shotgun surgery, duplicate code, inheritance issues, and coupling smells.

3. **OO metrics** — Computed in `SmellDetector.finalize()` using `ClassInfo` data: LCOM, CBO, fan-out, RFC, middle-man ratio.

4. **CLI/output** — `main()` parses args, calls `scan_paths()`, applies baseline filtering + inline suppression (`# noqa`), formats output.

### Key data structures

- `RuleDef` — rule metadata (rule_id, name, family, scope, severity)
- `Finding` — detection result (file, line, pattern, name, severity, message)
- `ClassInfo` — per-class OO metrics collected during AST walk
- `FileData` — per-file summary passed to cross-file analysis
- `_RULE_REGISTRY` — maps SC codes (`SC701`) to `RuleDef`

### Rule naming

SC codes are the sole identifier: SC1xx (state), SC2xx (functions), SC3xx (types), SC4xx (control), SC5xx (architecture), SC6xx (hygiene), SC7xx (idioms), SC8xx (metrics).

SC codes work in `--select`, `--ignore`, and `# noqa` comments.

## Adding a new check

**Per-file**: Add `_check_<name>()` to `SmellDetector`, call it from the appropriate `visit_*()`, add a `_RULE_REGISTRY` entry, add a test.

**Cross-file**: Add `_detect_<name>(all_data)` function, call it from `cross_file_analysis()`. If new data is needed, extend `FileData` and populate in `SmellDetector.finalize()`.

## Conventions

- **Zero dependencies** is a hard constraint. Stdlib only.
- **Conventional commits**: `feat:`, `fix:`, `docs:`, `test:`, `chore:` (release-please generates CHANGELOG).
- **Feature branches only** — pre-commit and pre-push hooks block direct commits/pushes to main.
- **Doc staleness hook** warns (non-blocking) when code changes without README/CONTRIBUTING/SKILL.md updates.
- Tests use `_write_py(tmp_path, code)` to create temp files and `scan_path(p)` to get findings. CLI tests use `_run_cli(*args)`.

## Project layout

- `src/smellcheck/detector.py` — entire implementation
- `src/smellcheck/__init__.py` — public API re-exports: `Finding`, `RuleDef`, `SmellDetector`, `scan_path`, `print_findings`
- `tests/test_detector.py` — main test suite
- `tests/test_regressions.py` — edge cases and false-positive guards
- `tests/test_version_parity.py` — ensures version consistency across config files
- `plugins/python-refactoring/` — Agent Skills plugin with SKILL.md and 8 reference files (the 82-pattern refactoring catalog)
