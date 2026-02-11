<p align="center">
  <img src="assets/logo.png" alt="smellcheck logo" width="200">
</p>

<h1 align="center">smellcheck</h1>

<p align="center">
  <strong>Python Code Smell Detector & Refactoring Guide</strong><br>
  82 refactoring patterns &middot; 55 automated AST checks &middot; zero dependencies
</p>

<p align="center">
  <a href="https://pypi.org/project/smellcheck/"><img src="https://img.shields.io/pypi/v/smellcheck" alt="PyPI"></a>
  <a href="https://pypi.org/project/smellcheck/"><img src="https://img.shields.io/pypi/pyversions/smellcheck" alt="Python"></a>
  <a href="https://github.com/cheickmec/smellcheck/actions/workflows/ci.yml"><img src="https://github.com/cheickmec/smellcheck/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypistats.org/packages/smellcheck"><img src="https://img.shields.io/pypi/dm/smellcheck" alt="Downloads"></a>
  <a href="https://github.com/cheickmec/smellcheck#pre-commit"><img src="https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit" alt="pre-commit"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json" alt="Ruff"></a>
  <a href="https://github.com/cheickmec/smellcheck/blob/main/LICENSE"><img src="https://img.shields.io/github/license/cheickmec/smellcheck" alt="License"></a>
</p>

**smellcheck** is a Python code smell detector and refactoring catalog. It works as a pip-installable CLI, GitHub Action, pre-commit hook, or [Agent Skills](https://agentskills.io) plugin for AI coding assistants.

**No dependencies.** Pure Python stdlib (`ast`, `pathlib`, `json`). Runs anywhere Python 3.10+ runs.

## Installation

### pip

```bash
pip install smellcheck

smellcheck src/
smellcheck myfile.py --format json
smellcheck src/ --min-severity warning --fail-on warning
```

### GitHub Action

```yaml
- uses: cheickmec/smellcheck@v1
  with:
    paths: 'src/'
    fail-on: 'error'       # exit 1 on error-level findings (default)
    min-severity: 'info'   # display all findings (default)
    format: 'github'       # GitHub annotations (default)
```

### pre-commit

```yaml
repos:
  - repo: https://github.com/cheickmec/smellcheck
    rev: v0.2.0
    hooks:
      - id: smellcheck
        args: ['--fail-on', 'warning']
```

### Agent Skills (Claude Code, Codex CLI, Cursor, Copilot, Roo Code, Gemini CLI)

Any tool supporting the Agent Skills standard can install directly:

```bash
# Claude Code
/plugin marketplace add cheickmec/smellcheck
/plugin install python-refactoring@smellcheck

# OpenAI Codex CLI
$skill-installer install cheickmec/smellcheck

# Cursor
# Import from GitHub URL in skills settings

# Or install from a local clone
git clone https://github.com/cheickmec/smellcheck.git
# Point your tool to plugins/python-refactoring/skills/python-refactoring/
```

### Manual setup for other tools

For tools without Agent Skills support (Aider, Windsurf, Continue.dev, Amazon Q), copy the relevant files into your project's instruction directory:

- Copy `SKILL.md` content into your tool's instruction file (`.cursorrules`, `CONVENTIONS.md`, `.windsurf/rules/`, etc.)
- Install with `pip install smellcheck` and run the `smellcheck` CLI

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

# Filter by severity
smellcheck src/ --min-severity warning

# Control exit code
smellcheck src/ --fail-on warning   # exit 1 on warning or error
smellcheck src/ --fail-on info      # exit 1 on any finding

# Run only specific checks
smellcheck src/ --select 001,057,CC

# Skip specific checks
smellcheck src/ --ignore 003,006

# Module execution
python -m smellcheck src/
```

## Configuration

smellcheck reads `[tool.smellcheck]` from the nearest `pyproject.toml`:

```toml
[tool.smellcheck]
select = ["001", "002", "057"]       # only run these checks (default: all)
ignore = ["003", "006"]              # skip these checks
per-file-ignores = {"tests/*" = ["002", "034"]}  # per-path overrides
fail-on = "warning"                  # override default fail-on
format = "text"                      # override default format
```

CLI flags override config values.

## Inline Suppression

Add `# noqa: SC057` to a line to suppress pattern #057 on that line:

```python
def foo(x=[]):  # noqa: SC057
    return x
```

Use `# noqa` (no codes) to suppress all findings on that line. Multiple codes: `# noqa: SC003,SC006`

## Features

- **55 automated smell checks** -- per-file AST analysis, cross-file dependency analysis, and OO metrics
- **82 refactoring patterns** -- numbered catalog with before/after examples, trade-offs, and severity levels
- **Zero dependencies** -- stdlib-only, runs on any Python 3.10+ installation
- **Multiple output formats** -- text (terminal), JSON (machine-readable), GitHub annotations (CI)
- **Configurable** -- pyproject.toml config, inline suppression, CLI overrides
- **Four distribution channels** -- pip, GitHub Action, pre-commit, Agent Skills

## Detected Patterns

### Per-File (40 checks)

| # | Pattern | Severity |
|---|---------|----------|
| 001 | Setters (half-built objects) | warning |
| 002 | Long functions (>20 lines) | warning |
| 003 | Magic numbers | info |
| 004 | Bare except / unused exception variable | warning |
| 006 | Generic names (data, result, tmp) | info |
| 007 | Extract class (too many methods) | info |
| 008 | UPPER_CASE without Final | info |
| 009 | Unprotected public attributes | info |
| 014 | isinstance chains | warning |
| 016 | Half-built objects (init assigns None) | warning |
| 017 | Boolean flag parameters | info |
| 018 | Singleton pattern | warning |
| 021 | Dead code after return | warning |
| 024 | Global mutable state | warning |
| 026 | input() in business logic | warning |
| 028 | Sequential IDs | info |
| 029 | Functions returning None or list | info |
| 033 | Excessive decorators (>3) | info |
| 034 | Too many parameters (>5) | warning |
| 036 | String concatenation for multiline | info |
| 039 | Deep nesting (>4 levels) | warning |
| 040 | Loop + append pattern | info |
| 041 | CQS violation (query + modify) | warning |
| 042 | Complex boolean expressions | warning |
| 051 | Error codes instead of exceptions | warning |
| 054 | Law of Demeter violation | info |
| 055 | Boolean control flag in loop | info |
| 057 | Mutable default arguments | error |
| 058 | open() without context manager | warning |
| 061 | Dataclass candidate | info |
| 062 | Sequential tuple indexing | info |
| 063 | contextlib candidate | info |
| CC | Cyclomatic complexity (>10) | warning |
| 064 | Unused function parameters | warning |
| 065 | Empty catch block | warning |
| 066 | Long lambda (>60 chars) | info |
| 067 | Complex comprehension (>2 generators) | warning |
| 068 | Missing default else branch | info |
| 069 | Lazy class (<2 methods) | info |
| 070 | Temporary fields | warning |

### Cross-File (10 checks)

| # | Pattern | Description |
|---|---------|-------------|
| 013 | Duplicate functions | AST-normalized hashing across files |
| CYC | Cyclic imports | DFS cycle detection |
| GOD | God modules | >500 lines or >30 top-level definitions |
| FE | Feature envy | Function accesses external attributes more than own |
| SHO | Shotgun surgery | Function called from >5 different files |
| DIT | Deep inheritance | Inheritance depth >4 |
| WHI | Wide hierarchy | >5 direct subclasses |
| INT | Inappropriate intimacy | >3 bidirectional class references between files |
| SPG | Speculative generality | Abstract class with no concrete subclasses |
| UDE | Unstable dependency | Stable module depends on unstable module |

### OO Metrics (5 checks)

| # | Metric | Threshold |
|---|--------|-----------|
| LCOM | Lack of Cohesion of Methods | >0.8 |
| CBO | Coupling Between Objects | >8 |
| FIO | Excessive Fan-Out | >15 |
| RFC | Response for a Class | >20 |
| MID | Middle Man (delegation ratio) | >50% |

## Refactoring Reference Files

Each pattern includes a description, before/after code examples, and trade-offs:

| File | Patterns |
|------|----------|
| `state.md` | Immutability, setters, attributes (001, 008, 009, 016, 017, 030) |
| `functions.md` | Extraction, naming, parameters, CQS (002, 010, 020, 026, 027, 034, 037, 041, 050, 052, 064, 066) |
| `types.md` | Classes, reification, polymorphism, nulls (007, 012, 014, 015, 019, 022, 023, 029, 038, 044, 048, 069, 070, DIT, WHI) |
| `control.md` | Guards, pipelines, conditionals, phases (039-043, 046, 047, 049, 053, 055, 056, 067, 068) |
| `architecture.md` | DI, singletons, exceptions, delegates (018, 024, 028, 035, 045, 051, 054, SHO, INT, SPG, UDE) |
| `hygiene.md` | Constants, dead code, comments, style (003, 004, 011, 013, 021, 025, 031-033, 036, 065) |
| `idioms.md` | Context managers, generators, unpacking (057-063) |
| `metrics.md` | OO metrics: cohesion, coupling, fan-out, response, delegation (LCOM, CBO, FIO, RFC, MID) |

## Compatibility

| Tool | Install Method | Status |
|------|---------------|--------|
| pip | `pip install smellcheck` | Native support |
| GitHub Actions | `uses: cheickmec/smellcheck@v1` | Native support |
| pre-commit | `.pre-commit-config.yaml` | Native support |
| Claude Code | `/plugin install` | Native support |
| OpenAI Codex CLI | `$skill-installer` | Native support |
| Cursor | GitHub import / `.cursor/skills/` | Native support |
| GitHub Copilot | MCP gallery | Native support |
| Roo Code | `.roo/` directory | Native support |
| Gemini CLI | Agent Skills | Native support |
| Windsurf | Copy to `.windsurf/rules/` | Manual |
| Aider | `--read CONVENTIONS.md` | Manual |
| Continue.dev | `.continue/rules/` | Manual |
| Amazon Q | `.amazonq/rules/` | Manual |

## How It Compares

| Feature | smellcheck | PyExamine | SMART-Dal | Pyscent |
|---------|------------|-----------|-----------|---------|
| Automated detections | 55 | 49 | 31 | 11 |
| Refactoring guidance | 82 patterns | None | None | None |
| Dependencies | 0 (stdlib) | pylint, radon | DesigniteJava | pylint, radon, cohesion |
| Python-specific idioms | Yes | No | No | No |
| Cross-file analysis | Yes | Limited | Yes | No |
| OO metrics | 6 | 19 | 0 | 1 |
| Distribution channels | 4 (pip, GHA, pre-commit, Agent Skills) | 1 | 1 | 1 |

## Contributing

Contributions welcome. The core detector is `src/smellcheck/detector.py` -- add new checks by extending the `SmellDetector` AST visitor class and adding a cross-file analysis function if needed.

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
