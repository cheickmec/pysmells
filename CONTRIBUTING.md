# Contributing to smellcheck

Thanks for your interest in contributing. smellcheck is a focused tool -- a zero-dependency Python code smell detector built entirely on stdlib. Contributions that preserve that simplicity are welcome.

## Development setup

```bash
git clone https://github.com/cheickmec/smellcheck.git
cd smellcheck
python -m venv .venv && source .venv/bin/activate
pip install -e .
pip install pytest pre-commit
pre-commit install
```

## Running tests

```bash
pytest tests/ -v
```

Self-check (smellcheck analyzing itself):

```bash
smellcheck src/smellcheck/ --min-severity warning
```

## Project structure

```
src/smellcheck/
  detector.py    # The entire detector: AST visitor, cross-file analysis, CLI
  __init__.py    # Public API + version
  __main__.py    # python -m smellcheck
```

The detector is intentionally a single file. The code is tightly coupled (AST visitor + cross-file passes + output formatting) and works well as one unit. Don't split it into modules without a strong reason.

## Adding a new smell check

### Per-file check (AST-based)

1. Add a `_check_<name>` method to the `SmellDetector` class
2. Call it from the appropriate `visit_*` method (e.g., `visit_FunctionDef`, `visit_If`)
3. Use `self._add(line, rule_id, name, severity, message, category)` to report findings
4. Rule ID format: `SCxxx` where the series encodes the category (e.g., `SC2xx` for functions, `SC7xx` for idioms)
5. Add a test in `tests/test_detector.py`

Example:

```python
def _check_too_many_returns(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
    """SC211 -- Function with too many return statements."""
    returns = [n for n in ast.walk(node) if isinstance(n, ast.Return)]
    if len(returns) > 5:
        self._add(node.lineno, "SC211", "Too Many Returns", "info",
                  f"`{node.name}` has {len(returns)} return statements",
                  "functions")
```

### Cross-file check

1. Add a `_detect_<name>(all_data: list[FileData]) -> list[Finding]` function
2. Call it from `cross_file_analysis()`
3. If you need new per-file metadata, add fields to `FileData` and populate them in `SmellDetector`

### Thresholds

Configurable thresholds live at the top of `detector.py` as `Final` constants. If your check has a numeric threshold, add it there.

## Code style

- **Zero dependencies.** Do not add imports beyond Python stdlib. This is a hard rule.
- **Python 3.10+.** Use `|` unions, pattern matching, modern features.
- **Type hints** on all public functions.
- No linter is configured in the repo yet, but keep style consistent with the existing code.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add SC211 too-many-returns check
fix: false positive in SC702 with ExitStack
test: add regression test for elif duplicate findings
docs: update README with new check
```

Scopes are optional but helpful: `feat(detector):`, `fix(cli):`, `test(regression):`.

## Pull requests

1. Create a feature branch from `main`
2. Make your changes with tests
3. Ensure `pytest tests/ -v` passes (all tests, including version parity)
4. Open a PR against `main`

The PR template will guide you through the checklist.

## Reporting bugs

Use the [bug report template](https://github.com/cheickmec/smellcheck/issues/new?template=bug_report.md). Include:

- The Python code that triggered the issue
- Expected vs. actual output
- Your Python version

## Suggesting new checks

Open a [feature request](https://github.com/cheickmec/smellcheck/issues/new?template=feature_request.md). Describe:

- What code pattern the check would detect
- Why it's a smell (reference to Fowler, Contieri, or other literature is a plus)
- Before/after examples
