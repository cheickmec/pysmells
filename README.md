# pysmells

Python code smell detection and refactoring guidance for Claude Code.

**82 refactoring patterns** with an AST-based detector covering 55 automated checks -- zero external dependencies (stdlib only).

## What's Inside

- **AST-based smell detector** (`detect_smells.py`) -- scans Python files for 38 per-file smells, 11 cross-file smells, and 6 OO metrics
- **Refactoring catalog** -- 82 numbered patterns with before/after examples across 8 reference files
- **Claude Code skill** -- when installed, Claude can analyze code for smells and apply refactoring patterns on `/refactor`

## Install as Claude Code Plugin

```bash
# From a Claude Code session:
/plugin marketplace add cheickberthe/pysmells
/plugin install python-refactoring@pysmells
```

Or install directly from the repo:

```bash
claude plugin install /path/to/pysmells/plugins/python-refactoring
```

## Standalone Usage

The detector is a single Python file with zero dependencies (stdlib only -- `ast`, `pathlib`, `json`, `collections`, `re`).

```bash
# Scan a directory
python detect_smells.py src/

# Scan a single file
python detect_smells.py myfile.py

# JSON output
python detect_smells.py src/ --json

# Filter by severity
python detect_smells.py src/ --min-severity warning
```

## Detected Patterns

### Per-File (38 checks)

| # | Pattern | Severity |
|---|---------|----------|
| 001 | Setters (half-built objects) | warning |
| 002 | Long functions (>20 lines) | warning |
| 003 | Magic numbers | info |
| 004 | Bare except / unused exception variable | warning |
| 006 | Generic names (data, result, tmp) | info |
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

### Cross-File (11 checks)

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

### OO Metrics (6 checks)

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
| `types.md` | Classes, reification, polymorphism, nulls (007, 012, 014, 015, 019, 022, 023, 029, 038, 044, 048, 069, 070, DIT, WHI, MID) |
| `control.md` | Guards, pipelines, conditionals, phases (039-043, 046, 047, 049, 053, 055, 056, 067, 068) |
| `architecture.md` | DI, singletons, exceptions, delegates (018, 024, 028, 035, 045, 051, 054, SHO, INT, SPG, UDE) |
| `hygiene.md` | Constants, dead code, comments, style (003, 004, 011, 013, 021, 025, 031-033, 036, 065) |
| `idioms.md` | Context managers, generators, unpacking (057-063) |
| `metrics.md` | OO metrics: cohesion, coupling, fan-out, response (LCOM, CBO, FIO, RFC) |

## How It Compares

| Feature | pysmells | PyExamine | SMART-Dal | Pyscent |
|---------|----------|-----------|-----------|---------|
| Automated detections | 55 | 49 | 31 | 11 |
| Refactoring guidance | 82 patterns | None | None | None |
| Dependencies | 0 (stdlib) | pylint, radon | DesigniteJava | pylint, radon, cohesion |
| Python-specific idioms | Yes | No | No | No |
| Cross-file analysis | Yes | Limited | Yes | No |
| OO metrics | 6 | 19 | 0 | 1 |
| Claude Code integration | Native skill | No | No | No |

## License

MIT
