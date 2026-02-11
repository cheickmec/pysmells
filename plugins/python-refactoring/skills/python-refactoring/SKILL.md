---
name: python-refactoring
description: "Python refactoring catalog with 82 patterns covering immutability, class design, control flow, architecture, OO metrics, and Python idioms. Analyze code for smells and apply numbered refactoring patterns with before/after examples. Use when the user invokes /refactor or explicitly asks to refactor, clean up, or improve Python code quality."
---

# Python Refactoring Skill

82 refactoring patterns from Contieri's series, Fowler's catalog, OO metrics literature, and Python idioms.

## Modes

**Active Analysis** (default when given code): Identify smells -> map to patterns -> load relevant references -> apply refactorings with before/after -> note trade-offs.

**Reference Lookup** (when asked about a pattern by number/name): Load the relevant reference file -> present the pattern.

## Smell-to-Pattern Map

| Code Smell | Patterns | File |
|---|---|---|
| Setters / half-built objects | 001, 016 | state.md |
| Mutable default args | 057 | idioms.md |
| Unprotected public attributes | 009 | state.md |
| Magic numbers / constants | 003 | hygiene.md |
| Variables that never change | 008 | state.md |
| Boolean flags for roles/states | 017 | state.md |
| Stale cached/derived attributes | 030 | state.md |
| Long function, multiple concerns | 002, 010 | functions.md |
| Comments replacing code | 005 | functions.md |
| Comments explaining what code does | 011 | hygiene.md |
| Generic names (result, data, tmp) | 006 | functions.md |
| Duplicated logic | 013 | hygiene.md |
| Near-duplicate functions | 050 | functions.md |
| Long related parameter lists | 034, 052 | functions.md |
| Query + modify in same function | 041 | functions.md |
| Static functions hiding deps | 020 | functions.md |
| `input()` in business logic | 026 | functions.md |
| Getters exposing data | 027 | functions.md |
| Need to test private methods | 037 | functions.md |
| Unused function parameters | 064 | functions.md |
| Long lambda expressions | 066 | functions.md |
| Type-checking if/elif chains | 014 | types.md |
| `isinstance()` dispatch | 060 | idioms.md |
| Dicts as objects (stringly-typed) | 012 | types.md |
| Raw primitives with implicit rules | 019, 044 | types.md |
| Raw lists, no domain meaning | 038 | types.md |
| Boilerplate `__init__/__repr__/__eq__` | 061 | idioms.md |
| Related functions without a class | 007 | types.md |
| Sibling classes with duplicate behavior | 022 | types.md |
| Inheritance without "is-a" | 023 | types.md |
| Constructor needs descriptive name | 048 | types.md |
| Scattered `None` checks | 015, 029 | types.md |
| Lazy class (too few methods) | 069 | types.md |
| Temporary fields (used in few methods) | 070 | types.md |
| Deep nesting | 039 | control.md |
| Imperative loops with accumulation | 040 | control.md |
| Complex boolean expressions | 042 | control.md |
| Long expressions, no named parts | 043 | control.md |
| Loop doing two things | 046 | control.md |
| Parse/compute/format mixed | 047 | control.md |
| Clunky algorithm | 049 | control.md |
| Boolean flag controlling loop | 055 | control.md |
| Complex if/elif dispatch | 056 | control.md |
| Related statements scattered | 053 | control.md |
| Missing default else branch | 068 | control.md |
| Complex comprehensions | 067 | control.md |
| Singleton / global state | 018, 024 | architecture.md |
| Same exception for biz + infra | 035 | architecture.md |
| Chained `.attr.attr.attr` | 054 | architecture.md |
| No fail-fast assertions | 045 | architecture.md |
| Dead code / commented blocks | 021 | hygiene.md |
| Unused exceptions | 004 | hygiene.md |
| Empty catch blocks | 065 | hygiene.md |
| Giant regex | 025 | hygiene.md |
| Excessive decorators | 033 | hygiene.md |
| String concatenation for multiline | 036 | hygiene.md |
| Inconsistent formatting | 032 | hygiene.md |
| Cryptic error messages | 031 | hygiene.md |
| Sequential IDs leaking info | 028 | architecture.md |
| Error codes instead of exceptions | 051 | architecture.md |
| Manual try/finally cleanup | 058, 063 | idioms.md |
| Full lists when streaming works | 059 | idioms.md |
| Indexing tuples by position | 062 | idioms.md |
| Shotgun surgery (wide call spread) | SHO | architecture.md |
| Deep inheritance tree | DIT | types.md |
| Wide hierarchy (too many subclasses) | WHI | types.md |
| Inappropriate intimacy | INT | architecture.md |
| Speculative generality (unused ABCs) | SPG | architecture.md |
| Unstable dependency | UDE | architecture.md |
| Low class cohesion (LCOM) | LCOM | metrics.md |
| High coupling between objects (CBO) | CBO | metrics.md |
| Excessive fan-out | FIO | metrics.md |
| High response for class (RFC) | RFC | metrics.md |
| Middle man (excessive delegation) | MID | metrics.md |

## Reference Files

Load **only** the file(s) matching detected smells:

- `references/state.md` -- Immutability, setters, attributes (001, 008, 009, 016, 017, 030)
- `references/functions.md` -- Method extraction, naming, parameters, CQS (002, 005, 006, 010, 020, 026, 027, 034, 037, 041, 050, 052, 064, 066)
- `references/types.md` -- Class design, reification, polymorphism, nulls (007, 012, 014, 015, 019, 022, 023, 029, 038, 044, 048, 069, 070, DIT, WHI)
- `references/control.md` -- Guard clauses, pipelines, conditionals, phases (039-043, 046, 047, 049, 053, 055, 056, 067, 068)
- `references/architecture.md` -- DI, singletons, exceptions, delegates (018, 024, 028, 035, 045, 051, 054, SHO, INT, SPG, UDE)
- `references/hygiene.md` -- Constants, dead code, comments, style (003, 004, 011, 013, 021, 025, 031-033, 036, 065)
- `references/idioms.md` -- Context managers, generators, unpacking, protocols (057-063)
- `references/metrics.md` -- OO metrics: cohesion, coupling, fan-out, response, delegation (LCOM, CBO, FIO, RFC, MID)

## Automated Smell Detector

`scripts/detect_smells.py` -- stdlib-only AST walker that programmatically detects 55 patterns (40 per-file + 10 cross-file + 5 OO metrics).

```bash
python scripts/detect_smells.py src/              # scan directory
python scripts/detect_smells.py myfile.py --json   # JSON output
python scripts/detect_smells.py src/ --min-severity warning  # filter noise
```

**Per-file detections** (40): #001 setters, #002 long functions, #003 magic numbers, #004 bare except, #006 generic names, #007 extract class, #008 UPPER_CASE without Final, #009 public attrs, #014 isinstance chains, #016 half-built objects, #017 boolean flags, #018 singleton, #021 dead code after return, #024 global mutables, #026 input() in logic, #028 sequential IDs, #029 return None|list, #033 excessive decorators, #034 too many params, #036 string concatenation, #039 deep nesting, #040 loop+append, #041 CQS violation, #042 complex booleans, #051 error codes, #054 Law of Demeter, #055 control flags, #057 mutable defaults, #058 open without with, #061 dataclass candidate, #062 sequential indexing, #063 contextlib candidate, #CC cyclomatic complexity, #064 unused parameters, #065 empty catch block, #066 long lambda, #067 complex comprehension, #068 missing else, #069 lazy class, #070 temporary field.

**Cross-file detections** (10): #013 duplicate functions (AST-normalized hashing), #CYC cyclic imports (DFS), #GOD god modules, #FE feature envy, #SHO shotgun surgery, #DIT deep inheritance, #WHI wide hierarchy, #INT inappropriate intimacy, #SPG speculative generality, #UDE unstable dependency.

**OO metrics** (5): #LCOM lack of cohesion, #CBO coupling between objects, #FIO fan-out, #RFC response for class, #MID middle man.

Run the detector first for a quick scan, then use the reference files to understand and apply the suggested refactorings.

## Workflow

1. Optionally run `detect_smells.py` on the target code for automated findings
2. Receive code -> scan for smells using table (manual or from script output)
3. Map smells to pattern numbers
4. Read **only** the relevant reference file(s)
5. Present: "Found N smells -> applying #X, #Y, #Z"
6. Show refactored code with explanations
7. Note trade-offs and breaking changes

## Guidelines

- Prioritize structural refactorings over cosmetic
- Preserve existing tests -- refactoring changes structure, not behavior
- Group related changes when multiple patterns apply
- Flag changes to public API (breaking vs non-breaking)
- For large code, suggest incremental order rather than all-at-once
- When patterns conflict, explain the trade-off and recommend
