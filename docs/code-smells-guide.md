# What Are Code Smells?

**Code smells** are surface-level patterns in source code that suggest deeper design problems. They are not bugs — the code works — but they signal structural weaknesses that make code harder to read, maintain, and extend over time.

The term was popularized by Kent Beck and Martin Fowler in *Refactoring: Improving the Design of Existing Code* (1999). The core insight is that certain recurring patterns in code reliably predict future maintenance pain, even when the code is currently correct.

## Why They Matter

Code smells compound. A single long function is manageable. A codebase full of long functions, deep nesting, and duplicated logic becomes expensive to change safely. Smells are leading indicators — they tell you where bugs are likely to appear *next*, not where they are now.

Addressing smells early is cheaper than fixing the bugs they eventually cause:

- **Readability**: Smelly code takes longer to understand. New team members ramp up slower. Code reviews take longer.
- **Changeability**: Tightly coupled, deeply nested, or duplicated code resists modification. A one-line feature becomes a multi-file refactor.
- **Testability**: Code with too many responsibilities, global state, or hidden dependencies is hard to test in isolation.
- **Reliability**: Complex conditionals, missing error handling, and mutable shared state are where bugs hide.

## Categories

Code smells fall into broad families. Understanding the family helps you choose the right refactoring.

### Bloaters

Code that has grown too large to work with comfortably.

| Smell | What It Looks Like |
|-------|-------------------|
| Long function | A function that scrolls off screen; doing too many things |
| Large class | A class with dozens of methods; trying to be everything |
| Long parameter list | Functions taking 5+ arguments; hard to call correctly |
| Deep nesting | 4+ levels of indentation; hard to follow the logic |
| Complex conditionals | Boolean expressions requiring mental gymnastics to parse |

**The fix pattern**: Break things apart. Extract functions, extract classes, introduce parameter objects.

### Object-Orientation Abusers

Misuse of OO features, or failure to use them when appropriate.

| Smell | What It Looks Like |
|-------|-------------------|
| isinstance chains | Using `isinstance()` instead of polymorphism |
| Half-built objects | `__init__` assigns `None` and hopes someone fills it in later |
| Refused bequest | Subclass ignores or overrides most of its parent's behavior |
| Lazy class | A class that does almost nothing; not earning its complexity cost |

**The fix pattern**: Use polymorphism. Push behavior into the right class. Flatten unnecessary hierarchies.

### Change Preventers

Structures that make changes ripple across the codebase.

| Smell | What It Looks Like |
|-------|-------------------|
| Shotgun surgery | One logical change requires editing many files |
| Cyclic imports | Modules that depend on each other in a circle |
| Feature envy | A function that uses another class's data more than its own |
| Inappropriate intimacy | Two classes that know too much about each other's internals |

**The fix pattern**: Move behavior closer to the data it operates on. Break cycles. Introduce interfaces.

### Dispensables

Code that adds complexity without adding value.

| Smell | What It Looks Like |
|-------|-------------------|
| Dead code | Functions, branches, or variables that are never reached |
| Duplicate code | The same logic copy-pasted across multiple locations |
| Magic numbers | Literal values with no explanation of what they represent |
| Excessive decorators | Stacking decorators that obscure what a function actually does |

**The fix pattern**: Delete what's unused. Extract what's duplicated. Name what's unclear.

### Couplers

Code that creates excessive dependencies between components.

| Smell | What It Looks Like |
|-------|-------------------|
| Law of Demeter violation | Long chains like `order.customer.address.city.name` |
| Global mutable state | Module-level lists, dicts, or objects that anyone can modify |
| Singleton pattern | Global state disguised as a design pattern |
| Unstable dependency | Stable core module depending on a frequently-changing module |

**The fix pattern**: Depend on abstractions. Pass data explicitly. Limit what each component can see.

### Python-Specific Idiom Smells

Patterns that are technically valid but go against Python's design philosophy.

| Smell | What It Looks Like |
|-------|-------------------|
| Mutable default argument | `def f(items=[])` — the list is shared across all calls |
| `open()` without `with` | Resource leak if an exception occurs before `.close()` |
| Loop + append | `for x in xs: result.append(f(x))` instead of a comprehension |
| Manual context manager | `try/finally` instead of `@contextmanager` |
| Tuple indexing | `point[0], point[1]` instead of unpacking or named fields |

**The fix pattern**: Use the idiom Python provides. Comprehensions, context managers, unpacking, dataclasses.

## How to Think About Smells

### Smells Are Not Rules

A 25-line function is not automatically bad. A function with 6 parameters might be the clearest way to express a complex operation. Smells are heuristics — they tell you *where to look*, not *what to do*.

The right response to a detected smell is to ask: "Is this making the code harder to work with?" Sometimes the answer is no, and that's fine. Use `# noqa: SC057` to suppress a finding you've considered and accepted.

### Severity Guides Priority

smellcheck assigns three severity levels:

- **error**: Almost always a real problem (e.g., mutable default arguments, bare except)
- **warning**: Usually worth fixing (e.g., long functions, deep nesting)
- **info**: Worth knowing about, fix at your discretion (e.g., magic numbers, generic names)

Start with errors, work through warnings, and treat info-level findings as opportunities rather than obligations.

### Incremental Adoption

You don't need to fix every smell at once. For existing codebases:

1. Generate a **baseline**: `smellcheck src/ --generate-baseline > .smellcheck-baseline.json`
2. Run with the baseline so only **new** smells are flagged
3. Fix smells opportunistically when you're already changing a file
4. Periodically re-baseline as you reduce the count

## Further Reading

- Martin Fowler, *Refactoring: Improving the Design of Existing Code* (2nd ed., 2018) — the definitive reference
- Sandro Mancuso, *The Software Craftsman* (2014) — on professional standards and clean code culture
- smellcheck's [refactoring reference files](https://github.com/cheickmec/smellcheck/tree/main/plugins/python-refactoring/skills/python-refactoring/references) — before/after examples for all 82 patterns
