<p align="center">
  <img src="https://raw.githubusercontent.com/cheickmec/smellcheck/main/assets/logo.png" alt="smellcheck logo" width="200">
</p>

<h1 align="center">smellcheck</h1>

<p align="center">
  <strong>Python Code Smell Detector & Refactoring Guide</strong><br>
  83 refactoring patterns &middot; 56 automated AST checks &middot; zero dependencies
</p>

<p align="center">
  <a href="https://pypi.org/project/smellcheck/"><img src="https://img.shields.io/pypi/v/smellcheck" alt="PyPI"></a>
  <a href="https://pypi.org/project/smellcheck/"><img src="https://img.shields.io/pypi/pyversions/smellcheck" alt="Python"></a>
  <a href="https://github.com/cheickmec/smellcheck/actions/workflows/ci.yml"><img src="https://github.com/cheickmec/smellcheck/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypistats.org/packages/smellcheck"><img src="https://img.shields.io/pypi/dm/smellcheck" alt="Downloads"></a>
  <a href="https://github.com/cheickmec/smellcheck/blob/main/docs/installation.md#pre-commit"><img src="https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit" alt="pre-commit"></a>
  <a href="https://github.com/cheickmec/smellcheck/blob/main/LICENSE"><img src="https://img.shields.io/github/license/cheickmec/smellcheck" alt="License"></a>
</p>

**smellcheck** is a Python code smell detector and refactoring catalog. It works as a pip-installable CLI, GitHub Action, pre-commit hook, or [Agent Skills](https://agentskills.io) plugin for AI coding assistants.

**No dependencies.** Pure Python stdlib (`ast`, `pathlib`, `json`). Runs anywhere Python 3.10+ runs.

> **What are code smells?** Code smells are surface-level patterns in source code that hint at deeper design problems — not bugs, but structural weaknesses that make code harder to maintain, extend, or understand. [Learn more →](https://github.com/cheickmec/smellcheck/blob/main/docs/code-smells-guide.md)

## Installation

### pip

```bash
pip install smellcheck

smellcheck src/
smellcheck myfile.py --format json
smellcheck src/ --min-severity warning --fail-on warning
```

Also available as a **GitHub Action**, **pre-commit hook**, **SARIF/Code Scanning** integration, and **[Agent Skills](https://agentskills.io) plugin** for Claude Code, Cursor, Copilot, Gemini CLI, and more.

**[Full installation guide →](https://github.com/cheickmec/smellcheck/blob/main/docs/installation.md)**

## Usage

```bash
# Scan a directory
smellcheck src/

# Scan multiple files
smellcheck file1.py file2.py

# JSON output
smellcheck src/ --format json

# GitHub Actions annotations
smellcheck src/ --format github

# SARIF output (for GitHub Code Scanning)
smellcheck src/ --format sarif > results.sarif

# Filter by severity
smellcheck src/ --min-severity warning

# Control exit code
smellcheck src/ --fail-on warning   # exit 1 on warning or error
smellcheck src/ --fail-on info      # exit 1 on any finding

# Run only specific checks
smellcheck src/ --select SC101,SC701,SC210

# Skip specific checks
smellcheck src/ --ignore SC601,SC202

# Module execution
python3 -m smellcheck src/

# Generate a baseline of current findings
smellcheck src/ --generate-baseline > .smellcheck-baseline.json

# Only report findings not in the baseline
smellcheck src/ --baseline .smellcheck-baseline.json
```

## Configuration

smellcheck reads `[tool.smellcheck]` from the nearest `pyproject.toml`:

```toml
[tool.smellcheck]
select = ["SC101", "SC201", "SC701"]  # only run these checks (default: all)
ignore = ["SC601", "SC202"]          # skip these checks
per-file-ignores = {"tests/*" = ["SC201", "SC206"]}  # per-path overrides
fail-on = "warning"                  # override default fail-on
format = "text"                      # override default format
baseline = ".smellcheck-baseline.json"  # suppress known findings
```

CLI flags override config values.

## Inline Suppression

Add `# noqa: SC701` to a line to suppress that check on that line:

```python
def foo(x=[]):  # noqa: SC701
    return x
```

Use `# noqa` (no codes) to suppress all findings on that line. Multiple codes: `# noqa: SC601,SC202`

## Baseline

For large codebases, you can adopt smellcheck incrementally using a baseline file. The baseline records fingerprints of existing findings so only **new** issues are reported.

```bash
# 1. Generate a baseline from the current state
smellcheck src/ --generate-baseline > .smellcheck-baseline.json

# 2. Run with the baseline — only new findings are reported
smellcheck src/ --baseline .smellcheck-baseline.json

# 3. Or set it in pyproject.toml so every run uses it automatically
```

Fingerprints are resilient to line-number changes — renaming or moving code around won't break the baseline. When you fix a baselined smell, its entry is silently ignored.

`--generate-baseline` and `--baseline` are mutually exclusive.

## Features

- **56 automated smell checks** -- per-file AST analysis, cross-file dependency analysis, and OO metrics
- **83 refactoring patterns** -- numbered catalog with before/after examples, trade-offs, and severity levels
- **Zero dependencies** -- stdlib-only, runs on any Python 3.10+ installation
- **Multiple output formats** -- text (terminal), JSON (machine-readable), GitHub annotations (CI), SARIF 2.1.0 (Code Scanning)
- **Configurable** -- pyproject.toml config, inline suppression, CLI overrides
- **Baseline support** -- adopt incrementally by suppressing existing findings and only failing on new ones
- **Multiple distribution channels** -- pip, GitHub Action, pre-commit, Agent Skills ([full list](https://github.com/cheickmec/smellcheck/blob/main/docs/installation.md))

## Detected Patterns

Every rule is identified by an **SC code** (e.g. `SC701`). Use SC codes in `--select`, `--ignore`, and `# noqa` comments.

### Per-File (41 checks)

| SC Code | Pattern | Severity |
|---------|---------|----------|
| SC101 | Setters (half-built objects) | warning |
| SC102 | UPPER_CASE without Final | info |
| SC103 | Unprotected public attributes | info |
| SC104 | Half-built objects (init assigns None) | warning |
| SC105 | Boolean flag parameters | info |
| SC106 | Global mutable state | info |
| SC107 | Sequential IDs | info |
| SC201 | Long functions (>20 lines) | warning |
| SC202 | Generic names (data, result, tmp) | info |
| SC203 | input() in business logic | warning |
| SC204 | Functions returning None or list | info |
| SC205 | Excessive decorators (>3) | info |
| SC206 | Too many parameters (>5) | warning |
| SC207 | CQS violation (query + modify) | info |
| SC208 | Unused function parameters | warning |
| SC209 | Long lambda (>60 chars) | info |
| SC210 | Cyclomatic complexity (>10) | warning |
| SC301 | Extract class (too many methods) | info |
| SC302 | isinstance chains | warning |
| SC303 | Singleton pattern | warning |
| SC304 | Dataclass candidate | info |
| SC305 | Sequential tuple indexing | info |
| SC306 | Lazy class (<2 methods) | info |
| SC307 | Temporary fields | warning |
| SC401 | Dead code after return | warning |
| SC402 | Deep nesting (>4 levels) | warning |
| SC403 | Loop + append pattern | info |
| SC404 | Complex boolean expressions | warning |
| SC405 | Boolean control flag in loop | info |
| SC406 | Complex comprehension (>2 generators) | info |
| SC407 | Missing default else branch | info |
| SC501 | Error codes instead of exceptions | warning |
| SC502 | Law of Demeter violation | info |
| SC601 | Magic numbers | info |
| SC602 | Bare except / unused exception variable | error |
| SC603 | String concatenation for multiline | info |
| SC604 | contextlib candidate | info |
| SC605 | Empty catch block | warning |
| SC701 | Mutable default arguments | error |
| SC702 | open() without context manager | warning |
| SC703 | Blocking calls in async functions | warning |

### Cross-File (10 checks)

| SC Code | Pattern | Description |
|---------|---------|-------------|
| SC211 | Feature envy | Function accesses external attributes more than own |
| SC308 | Deep inheritance | Inheritance depth >4 |
| SC309 | Wide hierarchy | >5 direct subclasses |
| SC503 | Cyclic imports | DFS cycle detection |
| SC504 | God modules | >500 lines or >30 top-level definitions |
| SC505 | Shotgun surgery | Function called from >5 different files |
| SC506 | Inappropriate intimacy | >3 bidirectional class references between files |
| SC507 | Speculative generality | Abstract class with no concrete subclasses |
| SC508 | Unstable dependency | Stable module depends on unstable module |
| SC606 | Duplicate functions | AST-normalized hashing across files |

### OO Metrics (5 checks)

| SC Code | Metric | Threshold |
|---------|--------|-----------|
| SC801 | Lack of Cohesion of Methods | >0.8 |
| SC802 | Coupling Between Objects | >8 |
| SC803 | Excessive Fan-Out | >15 |
| SC804 | Response for a Class | >20 |
| SC805 | Middle Man (delegation ratio) | >50% |

## Refactoring Reference Files

Each pattern includes a description, before/after code examples, and trade-offs:

| File | Patterns |
|------|----------|
| [`state.md`](https://github.com/cheickmec/smellcheck/blob/main/plugins/python-refactoring/skills/python-refactoring/references/state.md) | Immutability, setters, attributes (SC101–SC107) |
| [`functions.md`](https://github.com/cheickmec/smellcheck/blob/main/plugins/python-refactoring/skills/python-refactoring/references/functions.md) | Extraction, naming, parameters, CQS (SC201–SC210) |
| [`types.md`](https://github.com/cheickmec/smellcheck/blob/main/plugins/python-refactoring/skills/python-refactoring/references/types.md) | Classes, reification, polymorphism, nulls (SC301–SC309) |
| [`control.md`](https://github.com/cheickmec/smellcheck/blob/main/plugins/python-refactoring/skills/python-refactoring/references/control.md) | Guards, pipelines, conditionals, phases (SC401–SC407) |
| [`architecture.md`](https://github.com/cheickmec/smellcheck/blob/main/plugins/python-refactoring/skills/python-refactoring/references/architecture.md) | DI, singletons, exceptions, delegates (SC501–SC508) |
| [`hygiene.md`](https://github.com/cheickmec/smellcheck/blob/main/plugins/python-refactoring/skills/python-refactoring/references/hygiene.md) | Constants, dead code, comments, style (SC601–SC606) |
| [`idioms.md`](https://github.com/cheickmec/smellcheck/blob/main/plugins/python-refactoring/skills/python-refactoring/references/idioms.md) | Context managers, generators, unpacking, async (SC701–SC703) |
| [`metrics.md`](https://github.com/cheickmec/smellcheck/blob/main/plugins/python-refactoring/skills/python-refactoring/references/metrics.md) | OO metrics: cohesion, coupling, fan-out, response, delegation (SC801–SC805) |

## How It Compares

| Feature | smellcheck | [PyExamine](https://github.com/KarthikShivasankar/python_smells_detector) | [SMART-Dal](https://github.com/SMART-Dal/smell-detector-python) | [Pyscent](https://github.com/whyjay17/Pyscent) |
|---------|------------|-----------|-----------|---------|
| Automated detections | 56 | 49 | 31 | 11 |
| Refactoring guidance | 83 patterns | None | None | None |
| Dependencies | 0 (stdlib) | pylint, radon | DesigniteJava | pylint, radon, cohesion |
| Python-specific idioms | Yes | No | No | No |
| Cross-file analysis | Yes | Limited | Yes | No |
| OO metrics | 5 | 19 | 0 | 1 |
| Distribution channels | 4 (pip, GHA, pre-commit, Agent Skills) | 1 | 1 | 1 |

## Contributing

Contributions welcome — see [CONTRIBUTING.md](https://github.com/cheickmec/smellcheck/blob/main/CONTRIBUTING.md) for the full guide. The core detector is `src/smellcheck/detector.py`; add new checks by extending the `SmellDetector` AST visitor class and adding a cross-file analysis function if needed.

```bash
# Development setup
git clone https://github.com/cheickmec/smellcheck.git
cd smellcheck
pip install -e .
pip install pytest

# Run tests
pytest tests/ -v

# Self-check
smellcheck src/smellcheck/
```

## License

MIT
