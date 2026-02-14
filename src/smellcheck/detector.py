#!/usr/bin/env python3
"""
Python Code Smell Detector — SC-coded rules organized by family.

Self-contained: stdlib only (ast, pathlib, sys, json, collections, re, textwrap).
Detects 56 patterns programmatically (41 per-file + 10 cross-file + 5 OO metrics).

Usage:
    smellcheck path/to/file_or_dir [--format json] [--min-severity info]
    smellcheck src/ --format github
    smellcheck myfile.py --fail-on warning
    python -m smellcheck src/ --min-severity warning
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
import textwrap
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Final

# ---------------------------------------------------------------------------
# Finding data model
# ---------------------------------------------------------------------------

SEVERITY_ORDER: Final = {"info": 0, "warning": 1, "error": 2}

_VALID_FAMILIES: Final = frozenset(
    {
        "state",
        "functions",
        "types",
        "control",
        "architecture",
        "hygiene",
        "idioms",
        "metrics",
    }
)
_VALID_SCOPES: Final = frozenset({"file", "cross_file", "metric"})


@dataclass(frozen=True)
class RuleDef:
    """Metadata for a single smellcheck rule."""

    rule_id: str  # e.g. "SC701"
    name: str
    family: str  # state|functions|types|control|architecture|hygiene|idioms|metrics
    scope: str  # file|cross_file|metric
    default_severity: str


# fmt: off
_RULE_REGISTRY: dict[str, RuleDef] = {
    # --- Family 1: State & Immutability (SC1xx) ---
    "SC101": RuleDef("SC101", "Remove Setters", "state", "file", "warning"),
    "SC102": RuleDef("SC102", "Convert Variables to Constants", "state", "file", "info"),
    "SC103": RuleDef("SC103", "Protect Public Attributes", "state", "file", "info"),
    "SC104": RuleDef("SC104", "Build With The Essence", "state", "file", "warning"),
    "SC105": RuleDef("SC105", "Convert Attributes to Sets", "state", "file", "info"),
    "SC106": RuleDef("SC106", "Replace Global Variables with DI", "state", "file", "info"),
    "SC107": RuleDef("SC107", "Replace Sequential IDs", "state", "file", "info"),
    # --- Family 2: Functions (SC2xx) ---
    "SC201": RuleDef("SC201", "Extract Method", "functions", "file", "warning"),
    "SC202": RuleDef("SC202", "Rename Result Variables", "functions", "file", "info"),
    "SC203": RuleDef("SC203", "Replace input() Calls", "functions", "file", "warning"),
    "SC204": RuleDef("SC204", "Replace NULL with Collection", "functions", "file", "info"),
    "SC205": RuleDef("SC205", "Strip Annotations", "functions", "file", "info"),
    "SC206": RuleDef("SC206", "Reify Parameters", "functions", "file", "warning"),
    "SC207": RuleDef("SC207", "Separate Query from Modifier", "functions", "file", "info"),
    "SC208": RuleDef("SC208", "Remove Unused Parameters", "functions", "file", "warning"),
    "SC209": RuleDef("SC209", "Replace Long Lambda with Function", "functions", "file", "info"),
    "SC210": RuleDef("SC210", "Reduce Cyclomatic Complexity", "functions", "file", "warning"),
    "SC211": RuleDef("SC211", "Move Method (Feature Envy)", "functions", "cross_file", "info"),
    # --- Family 3: Types & Classes (SC3xx) ---
    "SC301": RuleDef("SC301", "Extract Class", "types", "file", "info"),
    "SC302": RuleDef("SC302", "Replace IF with Polymorphism", "types", "file", "warning"),
    "SC303": RuleDef("SC303", "Replace Singleton", "types", "file", "warning"),
    "SC304": RuleDef("SC304", "Replace Class with Dataclass", "types", "file", "info"),
    "SC305": RuleDef("SC305", "Use Unpacking Instead of Indexing", "types", "file", "info"),
    "SC306": RuleDef("SC306", "Remove Lazy Class", "types", "file", "info"),
    "SC307": RuleDef("SC307", "Remove Temporary Field", "types", "file", "info"),
    "SC308": RuleDef("SC308", "Deep Inheritance Tree", "types", "cross_file", "warning"),
    "SC309": RuleDef("SC309", "Wide Hierarchy", "types", "cross_file", "info"),
    # --- Family 4: Control Flow (SC4xx) ---
    "SC401": RuleDef("SC401", "Remove Dead Code", "control", "file", "warning"),
    "SC402": RuleDef("SC402", "Replace Nested Conditional with Guard Clauses", "control", "file", "warning"),
    "SC403": RuleDef("SC403", "Replace Loop with Pipeline", "control", "file", "info"),
    "SC404": RuleDef("SC404", "Decompose Conditional", "control", "file", "warning"),
    "SC405": RuleDef("SC405", "Replace Control Flag with Break", "control", "file", "info"),
    "SC406": RuleDef("SC406", "Simplify Complex Comprehension", "control", "file", "info"),
    "SC407": RuleDef("SC407", "Add Default Else Branch", "control", "file", "info"),
    # --- Family 5: Architecture (SC5xx) ---
    "SC501": RuleDef("SC501", "Replace Error Codes with Exceptions", "architecture", "file", "warning"),
    "SC502": RuleDef("SC502", "Law of Demeter", "architecture", "file", "info"),
    "SC503": RuleDef("SC503", "Break Cyclic Import", "architecture", "cross_file", "warning"),
    "SC504": RuleDef("SC504", "Split God Module", "architecture", "cross_file", "warning"),
    "SC505": RuleDef("SC505", "Shotgun Surgery", "architecture", "cross_file", "info"),
    "SC506": RuleDef("SC506", "Inappropriate Intimacy", "architecture", "cross_file", "info"),
    "SC507": RuleDef("SC507", "Remove Speculative Generality", "architecture", "cross_file", "info"),
    "SC508": RuleDef("SC508", "Unstable Dependency", "architecture", "cross_file", "info"),
    # --- Family 6: Hygiene (SC6xx) ---
    "SC601": RuleDef("SC601", "Extract Constant", "hygiene", "file", "info"),
    "SC602": RuleDef("SC602", "Remove Unhandled Exceptions", "hygiene", "file", "error"),
    "SC603": RuleDef("SC603", "Replace String Concatenation", "hygiene", "file", "info"),
    "SC604": RuleDef("SC604", "Replace with contextlib", "hygiene", "file", "info"),
    "SC605": RuleDef("SC605", "Remove Empty Catch Block", "hygiene", "file", "warning"),
    "SC606": RuleDef("SC606", "Remove Duplicated Code", "hygiene", "cross_file", "warning"),
    # --- Family 7: Idioms (SC7xx) ---
    "SC701": RuleDef("SC701", "Replace Mutable Default Arguments", "idioms", "file", "error"),
    "SC702": RuleDef("SC702", "Use Context Managers", "idioms", "file", "warning"),
    "SC703": RuleDef("SC703", "Avoid Blocking Calls in Async Functions", "idioms", "file", "warning"),
    # --- Family 8: Metrics (SC8xx) ---
    "SC801": RuleDef("SC801", "Low Class Cohesion", "metrics", "metric", "warning"),
    "SC802": RuleDef("SC802", "High Coupling Between Objects", "metrics", "metric", "warning"),
    "SC803": RuleDef("SC803", "Excessive Fan-Out", "metrics", "metric", "info"),
    "SC804": RuleDef("SC804", "High Response for Class", "metrics", "metric", "info"),
    "SC805": RuleDef("SC805", "Remove Middle Man", "metrics", "metric", "info"),
}
# fmt: on

# fmt: off
# Descriptions for SARIF help metadata (rule_id -> smell description).
_RULE_DESCRIPTIONS: dict[str, str] = {
    # State & Immutability
    "SC101": "Mutable state via setters leads to half-built objects and unpredictable mutations.",
    "SC102": "Values that never change are declared as mutable variables instead of constants.",
    "SC103": "Exposed public attributes let anyone mutate internal state arbitrarily.",
    "SC104": "Objects created empty then populated piecemeal — callers see half-built state.",
    "SC105": "Boolean flags for every possible state or role instead of polymorphism or enums.",
    "SC106": "Hidden global mutable state makes functions impure and hard to test.",
    "SC107": "Sequential auto-incrementing IDs leak information and enable scraping.",
    # Functions
    "SC201": "Function is too long — doing multiple things that should be separate methods.",
    "SC202": "Generic variable names like 'result', 'data', 'tmp' obscure intent.",
    "SC203": "input() calls baked into business logic prevent testing and reuse.",
    "SC204": "Returning None or a list forces every caller to check the return type.",
    "SC205": "More decorators stacked on a function than lines of actual logic.",
    "SC206": "Long parameter list of loosely related values — consider a parameter object.",
    "SC207": "Function both returns a value and changes state (CQS violation).",
    "SC208": "Parameters declared in the signature but never referenced in the function body.",
    "SC209": "Lambda expression too long to read as a one-liner — use a named function.",
    "SC210": "Too many independent paths through a function, making it hard to test.",
    "SC211": "A method uses more attributes from another class than from its own.",
    # Types & Classes
    "SC301": "Related behavior is scattered across the codebase with no cohesive class.",
    "SC302": "Type-checking isinstance/if-elif chains — use polymorphism instead.",
    "SC303": "Singleton pattern: global shared state disguised as a design pattern.",
    "SC304": "Boilerplate __init__/__repr__/__eq__ that @dataclass would generate.",
    "SC305": "Accessing tuple/list elements by numeric index is cryptic and fragile.",
    "SC306": "Class has too few methods and fields to justify its existence.",
    "SC307": "Instance attributes set in __init__ but used in very few methods.",
    "SC308": "Inheritance chain deeper than 3 levels makes the hierarchy hard to follow.",
    "SC309": "A class with too many direct subclasses — overly broad abstraction.",
    # Control Flow
    "SC401": "Dead code: unused functions, unreachable branches, or commented-out blocks.",
    "SC402": "Deep nesting obscures the happy path — use guard clauses instead.",
    "SC403": "Imperative for-loop with .append() — use a list comprehension or pipeline.",
    "SC404": "Complex boolean expression that is hard to parse mentally.",
    "SC405": "Boolean flag variable controlling loop flow instead of break/continue.",
    "SC406": "Comprehension is too nested or too long to read easily.",
    "SC407": "if/elif chain without a final else branch to handle unexpected cases.",
    # Architecture
    "SC501": "Error codes returned instead of raising exceptions — callers forget to check.",
    "SC502": "Chained attribute access (Law of Demeter) couples you to the object graph.",
    "SC503": "Circular import: two or more modules import each other.",
    "SC504": "God module with too many top-level definitions trying to do everything.",
    "SC505": "Shotgun surgery: changing this symbol requires edits across many modules.",
    "SC506": "Two classes share too many internals, indicating inappropriate intimacy.",
    "SC507": "Abstract base class with no concrete implementations — speculative generality.",
    "SC508": "A stable module depends on a more volatile one, inverting the dependency direction.",
    # Hygiene
    "SC601": "Magic numbers or strings with no named constant to explain their meaning.",
    "SC602": "Bare except clause swallows all exceptions including KeyboardInterrupt.",
    "SC603": "String concatenation with + for multiline strings instead of f-strings or join.",
    "SC604": "Manual try/finally context manager that contextlib would simplify.",
    "SC605": "Exception handler with only 'pass' — silently swallowing errors.",
    "SC606": "Same logic copy-pasted in multiple places — extract a shared function.",
    # Idioms
    "SC701": "Mutable default argument (list/dict/set) is shared across all calls.",
    "SC702": "Manual open/close resource cleanup instead of a 'with' context manager.",
    "SC703": "Blocking I/O or sleep calls inside async functions freeze the event loop, preventing concurrent request handling.",
    # Metrics
    "SC801": "Class methods operate on disjoint attribute sets — low cohesion.",
    "SC802": "Class depends on too many other classes — high coupling.",
    "SC803": "Module or class calls too many distinct external classes — excessive fan-out.",
    "SC804": "Class response set is too large — too many callable methods.",
    "SC805": "Class delegates almost everything to another object — middle man.",
}
# fmt: on

# Human-readable family labels for --explain output.
_FAMILY_LABELS: Final[dict[str, str]] = {
    "state": "State & Immutability",
    "functions": "Functions",
    "types": "Types & Classes",
    "control": "Control Flow",
    "architecture": "Architecture",
    "hygiene": "Hygiene",
    "idioms": "Idioms",
    "metrics": "Metrics",
}

# Before/after examples for --explain.  Rules with clear code patterns get a
# (before, after) tuple; cross-file and metric rules get None.
# fmt: off
_RULE_EXAMPLES: dict[str, tuple[str, str] | None] = {
    # --- State & Immutability ---
    "SC101": (
        "class User:\n    def set_name(self, name):\n        self._name = name",
        "class User:\n    def __init__(self, name):\n        self._name = name",
    ),
    "SC102": (
        "tax_rate = 0.08\nprice = amount * tax_rate",
        "TAX_RATE = 0.08\nprice = amount * TAX_RATE",
    ),
    "SC103": (
        "class Account:\n    def __init__(self):\n        self.balance = 0",
        "class Account:\n    def __init__(self):\n        self._balance = 0\n\n    @property\n    def balance(self):\n        return self._balance",
    ),
    "SC104": (
        "user = User()\nuser.name = 'Alice'\nuser.age = 30",
        "user = User(name='Alice', age=30)",
    ),
    "SC105": (
        "class Employee:\n    is_manager = False\n    is_admin = False\n    is_contractor = False",
        "class Employee:\n    roles: set[str] = field(default_factory=set)",
    ),
    "SC106": (
        "db = None\ndef get_users():\n    return db.query('SELECT *')",
        "def get_users(db):\n    return db.query('SELECT *')",
    ),
    "SC107": (
        "next_id = 0\ndef create():\n    global next_id\n    next_id += 1\n    return next_id",
        "import uuid\ndef create():\n    return str(uuid.uuid4())",
    ),
    # --- Functions ---
    "SC201": (
        "def process(data):\n    # validate\n    ...\n    # transform\n    ...\n    # save\n    ...",
        "def process(data):\n    validate(data)\n    transformed = transform(data)\n    save(transformed)",
    ),
    "SC202": (
        "def get_user(id):\n    result = db.query(id)\n    return result",
        "def get_user(id):\n    user = db.query(id)\n    return user",
    ),
    "SC203": (
        "def greet():\n    name = input('Name: ')\n    print(f'Hi {name}')",
        "def greet(name: str):\n    print(f'Hi {name}')",
    ),
    "SC204": (
        "def find(name):\n    if found:\n        return [item]\n    return None",
        "def find(name):\n    if found:\n        return [item]\n    return []",
    ),
    "SC205": (
        "@log\n@trace\n@cache\n@retry\ndef add(a, b):\n    return a + b",
        "def add(a, b):\n    return a + b  # move cross-cutting concerns elsewhere",
    ),
    "SC206": (
        "def ship(name, street, city, state, zip, country, weight, method):\n    ...",
        "def ship(address: Address, package: Package):\n    ...",
    ),
    "SC207": (
        "def pop_and_count(items):\n    items.pop()\n    return len(items)",
        "def remove_last(items):\n    items.pop()\n\ndef count(items):\n    return len(items)",
    ),
    "SC208": (
        "def greet(name, age, title):\n    print(f'Hi {name}')",
        "def greet(name):\n    print(f'Hi {name}')",
    ),
    "SC209": (
        "transform = lambda x: x.strip().lower().replace(' ', '_')",
        "def to_slug(x):\n    return x.strip().lower().replace(' ', '_')",
    ),
    "SC210": (
        "def rate(x):\n    if x > 100:\n        if x > 200:\n            ...\n        elif x > 150:\n            ...\n    elif x > 50:\n        ...",
        "def rate(x):\n    return _high(x) if x > 100 else _low(x)\n\ndef _high(x): ...\ndef _low(x): ...",
    ),
    "SC211": None,  # cross-file — feature envy
    # --- Types & Classes ---
    "SC301": (
        "# price calc scattered across 5 modules\ndef calc_tax(p): ...\ndef calc_discount(p): ...",
        "class PriceCalculator:\n    def tax(self, p): ...\n    def discount(self, p): ...",
    ),
    "SC302": (
        "if isinstance(shape, Circle):\n    area = math.pi * shape.r ** 2\nelif isinstance(shape, Rect):\n    area = shape.w * shape.h",
        "class Circle:\n    def area(self): return math.pi * self.r ** 2\n\nclass Rect:\n    def area(self): return self.w * self.h",
    ),
    "SC303": (
        "class DB:\n    _instance = None\n    @classmethod\n    def get(cls):\n        if not cls._instance:\n            cls._instance = cls()\n        return cls._instance",
        "# Use dependency injection instead\ndef create_app(db):\n    ...",
    ),
    "SC304": (
        "class Point:\n    def __init__(self, x, y):\n        self.x = x\n        self.y = y\n    def __repr__(self): ...\n    def __eq__(self, o): ...",
        "@dataclass\nclass Point:\n    x: float\n    y: float",
    ),
    "SC305": (
        "coords = (10.5, 20.3)\nx = coords[0]\ny = coords[1]",
        "x, y = coords\n# or use a namedtuple / dataclass",
    ),
    "SC306": (
        "class Formatter:\n    def format(self, text):\n        return text.strip()",
        "def format_text(text):\n    return text.strip()",
    ),
    "SC307": (
        "class Report:\n    def __init__(self):\n        self._header = None  # only used in render()\n        self._footer = None  # only used in render()",
        "class Report:\n    def render(self, header, footer):\n        ...",
    ),
    "SC308": None,  # cross-file — deep inheritance
    "SC309": None,  # cross-file — wide hierarchy
    # --- Control Flow ---
    "SC401": (
        "def process(x):\n    return x\n    print('done')  # unreachable",
        "def process(x):\n    return x",
    ),
    "SC402": (
        "def check(user):\n    if user:\n        if user.active:\n            if user.verified:\n                return True\n    return False",
        "def check(user):\n    if not user:\n        return False\n    if not user.active:\n        return False\n    if not user.verified:\n        return False\n    return True",
    ),
    "SC403": (
        "result = []\nfor x in items:\n    result.append(x * 2)",
        "result = [x * 2 for x in items]",
    ),
    "SC404": (
        "if a and (b or c) and not (d and e):\n    ...",
        "is_eligible = a and (b or c)\nis_allowed = not (d and e)\nif is_eligible and is_allowed:\n    ...",
    ),
    "SC405": (
        "found = False\nfor item in items:\n    if item.match:\n        found = True\nif found: ...",
        "for item in items:\n    if item.match:\n        break",
    ),
    "SC406": (
        "result = [f(x) for xs in matrix for x in xs if x > 0 if x != skip]",
        "result = []\nfor xs in matrix:\n    for x in xs:\n        if x > 0 and x != skip:\n            result.append(f(x))",
    ),
    "SC407": (
        "if status == 'a':\n    ...\nelif status == 'b':\n    ...",
        "if status == 'a':\n    ...\nelif status == 'b':\n    ...\nelse:\n    raise ValueError(f'Unknown: {status}')",
    ),
    # --- Architecture ---
    "SC501": (
        "def save(data):\n    if not valid(data):\n        return -1  # error code\n    return 0",
        "def save(data):\n    if not valid(data):\n        raise ValidationError('invalid data')",
    ),
    "SC502": (
        "city = order.customer.address.city",
        "city = order.shipping_city()",
    ),
    "SC503": None,  # cross-file — cyclic import
    "SC504": None,  # cross-file — god module
    "SC505": None,  # cross-file — shotgun surgery
    "SC506": None,  # cross-file — inappropriate intimacy
    "SC507": None,  # cross-file — speculative generality
    "SC508": None,  # cross-file — unstable dependency
    # --- Hygiene ---
    "SC601": (
        "if retry_count > 3:\n    time.sleep(60)",
        "MAX_RETRIES = 3\nRETRY_DELAY = 60\nif retry_count > MAX_RETRIES:\n    time.sleep(RETRY_DELAY)",
    ),
    "SC602": (
        "try:\n    process()\nexcept:\n    pass",
        "try:\n    process()\nexcept (ValueError, OSError) as e:\n    logger.error(e)",
    ),
    "SC603": (
        "msg = 'Hello ' + name + ', welcome to ' + place",
        "msg = f'Hello {name}, welcome to {place}'",
    ),
    "SC604": (
        "lock.acquire()\ntry:\n    do_work()\nfinally:\n    lock.release()",
        "with lock:\n    do_work()",
    ),
    "SC605": (
        "try:\n    risky()\nexcept Exception:\n    pass",
        "try:\n    risky()\nexcept Exception:\n    logger.warning('risky() failed', exc_info=True)",
    ),
    "SC606": None,  # cross-file — duplicated code
    # --- Idioms ---
    "SC701": (
        "def add(item, items=[]):\n    items.append(item)\n    return items",
        "def add(item, items=None):\n    if items is None:\n        items = []\n    items.append(item)\n    return items",
    ),
    "SC702": (
        "f = open('data.txt')\ndata = f.read()\nf.close()",
        "with open('data.txt') as f:\n    data = f.read()",
    ),
    "SC703": (
        "async def handler(request):\n    time.sleep(5)\n    data = requests.get(url)",
        "async def handler(request):\n    await asyncio.sleep(5)\n    data = await aiohttp.get(url)",
    ),
    # --- Metrics ---
    "SC801": None,  # metric — low class cohesion (LCOM)
    "SC802": None,  # metric — high coupling (CBO)
    "SC803": None,  # metric — excessive fan-out
    "SC804": None,  # metric — high response for class (RFC)
    "SC805": None,  # metric — middle man
}
# fmt: on


@dataclass
class Finding:
    file: str
    line: int
    pattern: str  # e.g. "SC701"
    name: str  # e.g. "Remove Setters"
    severity: str  # info | warning | error
    message: str
    category: str  # state | functions | types | control | architecture | hygiene | idioms | metrics
    scope: str = ""  # file | cross_file | metric

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)


# ---------------------------------------------------------------------------
# ClassInfo: per-class metadata for OO metrics (Tier 2/3)
# ---------------------------------------------------------------------------


@dataclass
class ClassInfo:
    name: str
    filepath: str
    line: int
    bases: list[str] = field(default_factory=list)
    method_count: int = 0
    field_count: int = 0
    all_fields: list[str] = field(default_factory=list)
    methods_using_fields: dict[str, set[str]] = field(
        default_factory=dict
    )  # method -> fields accessed
    external_class_accesses: dict[str, int] = field(
        default_factory=dict
    )  # other_class -> access count
    external_method_calls: set[str] = field(
        default_factory=set
    )  # "ClassName.method" distinct calls
    delegation_count: int = 0  # methods that just delegate to another object
    non_dunder_method_count: int = 0
    is_abstract: bool = False
    abstract_methods: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Thresholds (configurable)
# ---------------------------------------------------------------------------

# --- Original thresholds ---
MAX_FUNCTION_LINES: Final = 25
MAX_PARAMS: Final = 5
MAX_NESTING_DEPTH: Final = 3
MAX_DECORATORS: Final = 3
MAX_CLASS_METHODS: Final = 12
MAX_CYCLOMATIC_COMPLEXITY: Final = 10
MAX_MODULE_TOPLEVEL_DEFS: Final = 30
MIN_DUPLICATE_LINES: Final = 8
FEATURE_ENVY_THRESHOLD: Final = 3
HASH_PREFIX_LEN: Final = 12
SEPARATOR_WIDTH: Final = 60
MAGIC_NUMBER_WHITELIST: Final = frozenset({0, 1, -1, 2, 0.0, 1.0, 0.5, 100, 10})
GENERIC_NAMES: Final = frozenset(
    {
        "result",
        "results",
        "res",
        "data",
        "tmp",
        "temp",
        "val",
        "ret",
        "output",
        "out",
        "obj",
        "item",
        "elem",
        "value",
        "info",
    }
)

# --- Tier 1: new per-file thresholds ---
MAX_LAMBDA_LENGTH: Final = 60  # characters of unparsed source
MAX_COMPREHENSION_GENERATORS: Final = 2  # nested for-clauses
MIN_LAZY_CLASS_METHODS: Final = 2  # fewer non-dunder methods = lazy
TEMP_FIELD_USAGE_RATIO: Final = 0.3  # field used in <30% of methods

# --- Tier 2: cross-file thresholds ---
SHOTGUN_SURGERY_THRESHOLD: Final = 5  # called from >N different files
MAX_INHERITANCE_DEPTH: Final = 4
MAX_DIRECT_SUBCLASSES: Final = 5
INTIMACY_THRESHOLD: Final = 3  # shared attribute accesses between class pairs

# --- Tier 3: OO metrics thresholds ---
MAX_LCOM: Final = 0.8  # lack of cohesion > threshold
MAX_CBO: Final = 8  # coupling between objects
MAX_FANOUT: Final = 15  # outgoing module dependencies
MAX_RFC: Final = 20  # response for a class
MIDDLE_MAN_RATIO: Final = 0.5  # >50% delegation methods


# ---------------------------------------------------------------------------
# Config loading ([tool.smellcheck] in pyproject.toml)
# ---------------------------------------------------------------------------

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]


def _find_pyproject(start: Path) -> Path | None:
    """Walk up from *start* to find the nearest pyproject.toml."""
    current = start.resolve()
    if current.is_file():
        current = current.parent
    for parent in [current, *current.parents]:
        candidate = parent / "pyproject.toml"
        if candidate.is_file():
            return candidate
    return None


def load_config(target: Path) -> dict:
    """Load ``[tool.smellcheck]`` from the nearest ``pyproject.toml``.

    Returns an empty dict when the section is absent or TOML cannot be parsed.
    """
    pyproject = _find_pyproject(target)
    if pyproject is None or tomllib is None:
        return {}
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return dict(data.get("tool", {}).get("smellcheck", {}))


# ---------------------------------------------------------------------------
# File-level caching (--no-cache / --cache-dir / --clear-cache)
# ---------------------------------------------------------------------------

_DEFAULT_CACHE_DIR: Final = ".smellcheck-cache"
_CACHE_VERSION: Final = 1


def _cache_key(source: str, config_hash: str, version: str) -> str:
    """Cache key combining content hash, config hash, and tool version.

    The compound key is hashed to guarantee a safe filename (hex only,
    no path separators regardless of what *version* contains).
    """
    raw = f"{hashlib.sha256(source.encode('utf-8')).hexdigest()}_{config_hash}_{version}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _config_hash(config: dict | None) -> str:
    """Deterministic hash of the config options that affect analysis.

    Only keys that change *which* checks run are included.  Keys like
    ``min-severity``, ``fail-on``, ``format``, ``cache``, ``cache-dir``,
    and ``baseline`` are post-filtering / output-only and do not affect
    the per-file findings that get cached.
    """
    if not config:
        return "noconfig"
    # Only hash keys that change which checks run or how they behave
    relevant = {
        k: config[k]
        for k in ("select", "ignore", "per-file-ignores")
        if k in config
    }
    return hashlib.sha256(
        json.dumps(relevant, sort_keys=True).encode()
    ).hexdigest()[:16]


def _serialize_finding(f: Finding) -> dict:
    """Convert a Finding to a JSON-serializable dict."""
    return {
        "file": f.file,
        "line": f.line,
        "pattern": f.pattern,
        "name": f.name,
        "severity": f.severity,
        "message": f.message,
        "category": f.category,
        "scope": f.scope,
    }


def _deserialize_finding(d: dict) -> Finding:
    """Restore a Finding from a cached dict."""
    return Finding(
        file=d["file"],
        line=d["line"],
        pattern=d["pattern"],
        name=d["name"],
        severity=d["severity"],
        message=d["message"],
        category=d["category"],
        scope=d.get("scope", ""),
    )


def _serialize_class_info(ci: ClassInfo) -> dict:
    """Convert a ClassInfo to a JSON-serializable dict."""
    return {
        "name": ci.name,
        "filepath": ci.filepath,
        "line": ci.line,
        "bases": ci.bases,
        "method_count": ci.method_count,
        "field_count": ci.field_count,
        "all_fields": ci.all_fields,
        "methods_using_fields": {
            k: sorted(v) for k, v in ci.methods_using_fields.items()
        },
        "external_class_accesses": ci.external_class_accesses,
        "external_method_calls": sorted(ci.external_method_calls),
        "delegation_count": ci.delegation_count,
        "non_dunder_method_count": ci.non_dunder_method_count,
        "is_abstract": ci.is_abstract,
        "abstract_methods": ci.abstract_methods,
    }


def _deserialize_class_info(d: dict) -> ClassInfo:
    """Restore a ClassInfo from a cached dict."""
    return ClassInfo(
        name=d["name"],
        filepath=d["filepath"],
        line=d["line"],
        bases=d.get("bases", []),
        method_count=d.get("method_count", 0),
        field_count=d.get("field_count", 0),
        all_fields=d.get("all_fields", []),
        methods_using_fields={
            k: set(v) for k, v in d.get("methods_using_fields", {}).items()
        },
        external_class_accesses=d.get("external_class_accesses", {}),
        external_method_calls=set(d.get("external_method_calls", [])),
        delegation_count=d.get("delegation_count", 0),
        non_dunder_method_count=d.get("non_dunder_method_count", 0),
        is_abstract=d.get("is_abstract", False),
        abstract_methods=d.get("abstract_methods", []),
    )


def _serialize_file_data(fd: FileData) -> dict:
    """Convert a FileData to a JSON-serializable dict."""
    return {
        "filepath": fd.filepath,
        "toplevel_defs": fd.toplevel_defs,
        "total_lines": fd.total_lines,
        "imports": fd.imports,
        "func_signatures": [list(t) for t in fd.func_signatures],
        "method_external_accesses": [
            [m, line, cls, acc]
            for m, line, cls, acc in fd.method_external_accesses
        ],
        "class_names": fd.class_names,
        "class_bases": fd.class_bases,
        "class_lines": fd.class_lines,
        "class_info": [_serialize_class_info(ci) for ci in fd.class_info],
        "defined_functions": sorted(fd.defined_functions),
        "called_functions": sorted(fd.called_functions),
        "abstract_classes": sorted(fd.abstract_classes),
    }


def _deserialize_file_data(d: dict) -> FileData:
    """Restore a FileData from a cached dict."""
    return FileData(
        filepath=d["filepath"],
        toplevel_defs=d.get("toplevel_defs", 0),
        total_lines=d.get("total_lines", 0),
        imports=d.get("imports", []),
        func_signatures=[tuple(t) for t in d.get("func_signatures", [])],
        method_external_accesses=[
            (m, line, cls, acc)
            for m, line, cls, acc in d.get("method_external_accesses", [])
        ],
        class_names=d.get("class_names", []),
        class_bases=d.get("class_bases", {}),
        class_lines=d.get("class_lines", {}),
        class_info=[
            _deserialize_class_info(ci) for ci in d.get("class_info", [])
        ],
        defined_functions=set(d.get("defined_functions", [])),
        called_functions=set(d.get("called_functions", [])),
        abstract_classes=set(d.get("abstract_classes", [])),
    )


def _read_cache(
    cache_dir: Path, key: str,
) -> tuple[list[Finding], FileData] | None:
    """Read cached per-file results.  Returns None on miss or corruption."""
    cache_file = cache_dir / f"{key}.json"
    if not cache_file.exists():
        return None
    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        if data.get("cache_version") != _CACHE_VERSION:
            return None
        findings = [_deserialize_finding(f) for f in data["findings"]]
        file_data = _deserialize_file_data(data["file_data"])
        return findings, file_data
    except Exception:
        # Corrupted cache entry — treat as miss
        try:
            cache_file.unlink()
        except OSError:
            pass
        return None


def _write_cache(
    cache_dir: Path,
    key: str,
    findings: list[Finding],
    file_data: FileData,
) -> None:
    """Write per-file results to cache.  Silent on failure."""
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"{key}.json"
        tmp = cache_file.with_suffix(".tmp")
        data = {
            "cache_version": _CACHE_VERSION,
            "findings": [_serialize_finding(f) for f in findings],
            "file_data": _serialize_file_data(file_data),
        }
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(cache_file)  # atomic on POSIX
    except OSError:
        pass


def _clear_cache(cache_dir: Path) -> int:
    """Delete all cache entries.  Returns number of files removed."""
    removed = 0
    if cache_dir.is_dir():
        for f in cache_dir.iterdir():
            if f.suffix in (".json", ".tmp"):
                try:
                    f.unlink()
                    removed += 1
                except OSError:
                    pass
    return removed


# ---------------------------------------------------------------------------
# Baseline support (--generate-baseline / --baseline)
# ---------------------------------------------------------------------------


def _normalize_message(msg: str) -> str:
    """Strip digits and collapse whitespace for fingerprint stability."""
    return re.sub(r"\s+", " ", re.sub(r"\d+", "", msg)).strip().lower()


def _fingerprint(finding: Finding, base_path: Path) -> str:
    """Line-number-resilient fingerprint. Uses (rel_file, pattern, norm_message)."""
    try:
        rel = Path(finding.file).resolve().relative_to(base_path.resolve()).as_posix()
    except ValueError:
        rel = Path(finding.file).name
    raw = f"{rel}\0{finding.pattern}\0{_normalize_message(finding.message)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:HASH_PREFIX_LEN]


def _generate_baseline_json(findings: list[Finding], base_path: Path) -> str:
    """Produce baseline JSON from current findings."""
    from datetime import datetime, timezone

    from smellcheck import __version__

    entries = []
    for f in findings:
        try:
            rel = Path(f.file).resolve().relative_to(base_path.resolve()).as_posix()
        except ValueError:
            rel = Path(f.file).name
        entries.append(
            {
                "fingerprint": _fingerprint(f, base_path),
                "file": rel,
                "pattern": f.pattern,
                "line": f.line,
                "name": f.name,
            }
        )
    return json.dumps(
        {
            "version": __version__,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "findings": entries,
        },
        indent=2,
    )


def _load_baseline(path: Path) -> set[str]:
    """Load fingerprints from a baseline file. Exits on error."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Error: baseline file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: invalid baseline JSON in {path}: {e}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(data, dict) or "findings" not in data:
        print(f"Error: baseline file missing 'findings' key: {path}", file=sys.stderr)
        sys.exit(1)
    return {entry["fingerprint"] for entry in data["findings"]}


def _filter_baseline(
    findings: list[Finding], baseline_fps: set[str], base_path: Path
) -> tuple[list[Finding], int]:
    """Remove baselined findings. Returns (new_findings, suppressed_count)."""
    new: list[Finding] = []
    suppressed = 0
    for f in findings:
        if _fingerprint(f, base_path) in baseline_fps:
            suppressed += 1
        else:
            new.append(f)
    return new, suppressed


# ---------------------------------------------------------------------------
# Inline suppression (# noqa: SC701,SC601)
# ---------------------------------------------------------------------------

_NOQA_RE = re.compile(r"#\s*noqa\b(?:\s*:\s*([A-Za-z0-9_,\s]+))?")


def _resolve_code(code: str) -> set[str]:
    """Resolve a code to its SC rule key in ``_RULE_REGISTRY``.

    Accepts SC codes like ``"SC701"``.
    Returns a set of matching registry keys (e.g. ``{"SC701"}``).
    """
    c = code.strip().upper()
    if not c:
        return set()
    if c in _RULE_REGISTRY:
        return {c}
    return set()


def _noqa_suppressed(source_lines: list[str], line: int, pattern: str) -> bool:
    """Return True if *line* (1-based) has a ``# noqa`` that covers *pattern*.

    ``# noqa`` alone suppresses everything.
    ``# noqa: SC701,SC601`` suppresses only the listed codes.
    """
    if line < 1 or line > len(source_lines):
        return False
    text = source_lines[line - 1]
    m = _NOQA_RE.search(text)
    if m is None:
        return False
    codes_str = m.group(1)
    if codes_str is None:
        return True  # bare ``# noqa`` suppresses all
    # Build set of patterns that the noqa line intends to suppress
    suppressed_patterns: set[str] = set()
    for raw_code in codes_str.split(","):
        suppressed_patterns.update(_resolve_code(raw_code))
    return pattern in suppressed_patterns


# ---------------------------------------------------------------------------
# Block-level suppression (# smellcheck: disable/enable)
# ---------------------------------------------------------------------------

# Matches: # smellcheck: disable SC701, SC301
#          # smellcheck: enable-all
#          # smellcheck: disable-file SC301
_DIRECTIVE_RE = re.compile(
    r"#\s*smellcheck\s*:\s*(disable-file|disable-all|enable-all|disable|enable)"
    r"(?:\s+([A-Za-z0-9_,\s]+))?",
)


def _parse_block_directives(
    source_lines: list[str],
) -> tuple[dict[str, list[tuple[int, int]]], bool, set[str]]:
    """Parse ``# smellcheck:`` directives and build a suppression map.

    Returns ``(block_map, disable_all_file, file_disabled_codes)`` where:

    * *block_map* maps each SC code to a list of ``(start, end)`` 1-based
      line ranges where the code is suppressed.
    * *disable_all_file* is True when ``# smellcheck: disable-file`` (no
      codes) appears — suppress every code for the entire file.
    * *file_disabled_codes* is the set of SC codes suppressed for the
      entire file via ``# smellcheck: disable-file SC...``.
    """
    total = len(source_lines)
    # Currently open disable ranges: code -> start line (1-based)
    open_ranges: dict[str, int] = {}
    all_open_since: int | None = None  # line where disable-all started

    block_map: dict[str, list[tuple[int, int]]] = {}
    disable_all_file = False
    file_disabled_codes: set[str] = set()

    for idx, text in enumerate(source_lines, start=1):
        m = _DIRECTIVE_RE.search(text)
        if m is None:
            continue
        action = m.group(1)
        codes_str = m.group(2)

        if action == "disable-file":
            if codes_str:
                for raw in codes_str.split(","):
                    file_disabled_codes.update(_resolve_code(raw))
            else:
                disable_all_file = True
            continue

        if action == "disable-all":
            all_open_since = idx
            continue

        if action == "enable-all":
            if all_open_since is not None:
                # Close all individually-opened ranges too
                for code, start in list(open_ranges.items()):
                    block_map.setdefault(code, []).append((start, idx))
                    del open_ranges[code]
                # Record the disable-all range with sentinel key "*"
                block_map.setdefault("*", []).append((all_open_since, idx))
                all_open_since = None
            continue

        # disable / enable with specific codes
        if not codes_str:
            continue  # bare disable/enable without codes → ignore
        resolved: set[str] = set()
        for raw in codes_str.split(","):
            resolved.update(_resolve_code(raw))

        if action == "disable":
            for code in resolved:
                if code not in open_ranges:
                    open_ranges[code] = idx
        elif action == "enable":
            for code in resolved:
                if code in open_ranges:
                    block_map.setdefault(code, []).append(
                        (open_ranges.pop(code), idx)
                    )

    # Close any unterminated ranges at EOF
    if all_open_since is not None:
        block_map.setdefault("*", []).append((all_open_since, total + 1))
        for code, start in open_ranges.items():
            block_map.setdefault(code, []).append((start, total + 1))
    else:
        for code, start in open_ranges.items():
            block_map.setdefault(code, []).append((start, total + 1))

    return block_map, disable_all_file, file_disabled_codes


def _is_suppressed(
    source_lines: list[str],
    line: int,
    pattern: str,
    block_map: dict[str, list[tuple[int, int]]] | None = None,
    disable_all_file: bool = False,
    file_disabled_codes: frozenset[str] | None = None,
) -> bool:
    """Return True if a finding at *line* for *pattern* should be suppressed.

    Checks (in order):
    1. Per-line ``# noqa`` (highest precedence)
    2. File-wide ``# smellcheck: disable-file``
    3. Block-level ``# smellcheck: disable/enable`` ranges
    """
    # 1. Per-line noqa always wins
    if _noqa_suppressed(source_lines, line, pattern):
        return True

    # 2. File-wide suppression
    if disable_all_file:
        return True
    if file_disabled_codes and pattern in file_disabled_codes:
        return True

    # 3. Block-level ranges (not applied to cross-file findings — those
    #    are about whole-file/module structure, not individual lines)
    if block_map:
        rule = _RULE_REGISTRY.get(pattern)
        if rule and rule.scope == "cross_file":
            return False
        # Check wildcard ranges (disable-all)
        for start, end in block_map.get("*", ()):
            if start <= line < end:
                return True
        # Check code-specific ranges
        for start, end in block_map.get(pattern, ()):
            if start <= line < end:
                return True

    return False


# ---------------------------------------------------------------------------
# Blocking calls in async functions (SC703)
# ---------------------------------------------------------------------------

# Maps call key -> (display_name, async_alternative)
_BLOCKING_CALLS: Final = {
    # Time
    "time.sleep": ("time.sleep()", "asyncio.sleep()"),
    # File I/O
    "open": ("open()", "aiofiles.open()"),
    # HTTP — requests
    "requests.get": ("requests.get()", "httpx.AsyncClient"),
    "requests.post": ("requests.post()", "httpx.AsyncClient"),
    "requests.put": ("requests.put()", "httpx.AsyncClient"),
    "requests.delete": ("requests.delete()", "httpx.AsyncClient"),
    "requests.patch": ("requests.patch()", "httpx.AsyncClient"),
    "requests.head": ("requests.head()", "httpx.AsyncClient"),
    "requests.options": ("requests.options()", "httpx.AsyncClient"),
    "requests.request": ("requests.request()", "httpx.AsyncClient"),
    # HTTP — urllib
    "urllib.request.urlopen": ("urllib.request.urlopen()", "httpx.AsyncClient"),
    # Subprocess
    "subprocess.run": ("subprocess.run()", "asyncio.create_subprocess_exec()"),
    "subprocess.call": ("subprocess.call()", "asyncio.create_subprocess_exec()"),
    "subprocess.check_call": ("subprocess.check_call()", "asyncio.create_subprocess_exec()"),
    "subprocess.check_output": ("subprocess.check_output()", "asyncio.create_subprocess_exec()"),
    "subprocess.Popen": ("subprocess.Popen()", "asyncio.create_subprocess_exec()"),
    "os.system": ("os.system()", "asyncio.create_subprocess_exec()"),
    "os.popen": ("os.popen()", "asyncio.create_subprocess_exec()"),
    # Socket
    "socket.create_connection": ("socket.create_connection()", "asyncio.open_connection()"),
    "socket.getaddrinfo": ("socket.getaddrinfo()", "loop.getaddrinfo()"),
    "socket.getnameinfo": ("socket.getnameinfo()", "loop.getnameinfo()"),
    # Input
    "input": ("input()", "asyncio stream reader"),
    # OS filesystem
    "os.listdir": ("os.listdir()", "asyncio.to_thread()"),
    "os.walk": ("os.walk()", "asyncio.to_thread()"),
    "os.remove": ("os.remove()", "asyncio.to_thread()"),
    "os.rename": ("os.rename()", "asyncio.to_thread()"),
    "os.mkdir": ("os.mkdir()", "asyncio.to_thread()"),
    "os.makedirs": ("os.makedirs()", "asyncio.to_thread()"),
    "os.stat": ("os.stat()", "asyncio.to_thread()"),
    "os.path.exists": ("os.path.exists()", "asyncio.to_thread()"),
    "os.path.isfile": ("os.path.isfile()", "asyncio.to_thread()"),
    "os.path.isdir": ("os.path.isdir()", "asyncio.to_thread()"),
    "os.path.getsize": ("os.path.getsize()", "asyncio.to_thread()"),
    # Serialization
    "pickle.load": ("pickle.load()", "asyncio.to_thread()"),
    "pickle.dump": ("pickle.dump()", "asyncio.to_thread()"),
}


def _walk_skip_nested_scopes(node: ast.AST):
    """Yield all descendant nodes, skipping nested function/lambda scopes."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        yield child
        yield from _walk_skip_nested_scopes(child)


def _is_to_thread_call(node: ast.Call) -> bool:
    """Return True if *node* is ``asyncio.to_thread(...)``."""
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "to_thread"
        and isinstance(func.value, ast.Name)
        and func.value.id == "asyncio"
    )


def _is_run_in_executor_call(node: ast.Call) -> bool:
    """Return True if *node* is ``<expr>.run_in_executor(...)``."""
    return isinstance(node.func, ast.Attribute) and node.func.attr == "run_in_executor"


def _get_blocking_call_key(node: ast.Call) -> str | None:
    """Extract a lookup key for *node* against ``_BLOCKING_CALLS``.

    Returns a dotted name (e.g. ``"time.sleep"``), a builtin name, or ``None``.
    """
    func = node.func
    # Builtin: open(...), input(...)
    if isinstance(func, ast.Name):
        return func.id if func.id in _BLOCKING_CALLS else None
    # Attribute chains: mod.func or mod.sub.func
    if isinstance(func, ast.Attribute):
        # Two-level: mod.sub.func  (e.g. os.path.exists)
        if isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
            key = f"{func.value.value.id}.{func.value.attr}.{func.attr}"
            if key in _BLOCKING_CALLS:
                return key
        # Single-level: mod.func  (e.g. time.sleep)
        if isinstance(func.value, ast.Name):
            key = f"{func.value.id}.{func.attr}"
            if key in _BLOCKING_CALLS:
                return key
    return None


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _lines_of(node: ast.AST) -> int:
    """Approximate line count of a node."""
    if hasattr(node, "end_lineno") and hasattr(node, "lineno"):
        return (node.end_lineno or node.lineno) - node.lineno + 1
    return 0


def _nesting_depth(node: ast.AST, _depth: int = 0) -> int:
    """Max nesting depth of control flow inside a node."""
    max_d = _depth
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
            max_d = max(max_d, _nesting_depth(child, _depth + 1))
        else:
            max_d = max(max_d, _nesting_depth(child, _depth))
    return max_d


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _is_mutable_literal(node: ast.AST) -> bool:
    return isinstance(node, (ast.List, ast.Dict, ast.Set))


def _get_assigned_names(targets: list[ast.AST]) -> list[str]:
    names = []
    for t in targets:
        if isinstance(t, ast.Name):
            names.append(t.id)
        elif isinstance(t, ast.Tuple | ast.List):
            names.extend(_get_assigned_names(t.elts))
    return names


def _cyclomatic_complexity(node: ast.AST) -> int:
    """Compute McCabe cyclomatic complexity of a function/method node."""
    cc = 1
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.IfExp)):
            cc += 1
        elif isinstance(child, (ast.For, ast.While, ast.AsyncFor)):
            cc += 1
        elif isinstance(child, ast.ExceptHandler):
            cc += 1
        elif isinstance(child, ast.With | ast.AsyncWith):
            cc += 1
        elif isinstance(child, ast.Assert):
            cc += 1
        elif isinstance(child, ast.BoolOp):
            cc += len(child.values) - 1
        elif isinstance(child, ast.comprehension):
            cc += 1
            cc += len(child.ifs)
    return cc


def _normalize_ast(node: ast.AST) -> str:
    """Produce a canonical string from an AST node for duplicate detection."""
    parts: list[str] = []

    def _walk(n: ast.AST):
        if (
            isinstance(n, ast.Expr)
            and isinstance(n.value, ast.Constant)
            and isinstance(n.value.value, str)
        ):
            parts.append("DOC")
            return
        parts.append(type(n).__name__)
        for child in ast.iter_child_nodes(n):
            if isinstance(child, ast.arguments):
                parts.append(f"ARGS({len(child.args)})")
                continue
            if isinstance(child, ast.Name):
                parts.append("NAME")
                continue
            if isinstance(child, ast.Constant):
                parts.append(f"CONST({type(child.value).__name__})")
                continue
            _walk(child)

    _walk(node)
    return "|".join(parts)


def _extract_imports(tree: ast.Module) -> list[str]:
    """Extract all imported module names from a module's AST.

    Returns both the full dotted path and all intermediate segments so that
    cross-file matching works for both package-style imports (``from pkg.sub import x``)
    and flat single-file imports (``import utils``).
    """
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # "import pkg_a.a" → ["pkg_a", "a", "pkg_a.a"]
                parts = alias.name.split(".")
                imports.extend(parts)
                if len(parts) > 1:
                    imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                parts = node.module.split(".")
                imports.extend(parts)
                if len(parts) > 1:
                    imports.append(node.module)
    return imports


def _is_stub_body(body: list[ast.stmt]) -> bool:
    """Check if a function body is just pass, ..., or a docstring."""
    if not body:
        return True
    stmts = body
    # Skip leading docstring
    if (
        isinstance(stmts[0], ast.Expr)
        and isinstance(stmts[0].value, ast.Constant)
        and isinstance(stmts[0].value.value, str)
    ):
        stmts = stmts[1:]
    if not stmts:
        return True  # docstring only
    if len(stmts) == 1:
        s = stmts[0]
        if isinstance(s, ast.Pass):
            return True
        if (
            isinstance(s, ast.Expr)
            and isinstance(s.value, ast.Constant)
            and s.value.value is ...
        ):
            return True
        if isinstance(s, ast.Raise):
            return True  # abstract-like raise NotImplementedError
    return False


def _has_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, names: set[str]
) -> bool:
    """Check if a node has any decorator with the given names."""
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name) and dec.id in names:
            return True
        if isinstance(dec, ast.Attribute) and dec.attr in names:
            return True
        if isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name) and dec.func.id in names:
                return True
            if isinstance(dec.func, ast.Attribute) and dec.func.attr in names:
                return True
    return False


# ---------------------------------------------------------------------------
# Cross-file data collected during first pass
# ---------------------------------------------------------------------------


@dataclass
class FileData:
    """Per-file metadata collected during scanning for cross-file analysis."""

    filepath: str
    toplevel_defs: int = 0
    total_lines: int = 0
    imports: list[str] = field(default_factory=list)
    # func_key -> (filepath, func_name, line, normalized_hash, line_count)
    func_signatures: list[tuple[str, str, int, str, int]] = field(default_factory=list)
    # method -> {external_class: count}
    method_external_accesses: list[tuple[str, int, str, dict[str, int]]] = field(
        default_factory=list
    )
    # class names defined in this file
    class_names: list[str] = field(default_factory=list)
    # --- Tier 2/3 additions ---
    class_bases: dict[str, list[str]] = field(
        default_factory=dict
    )  # class -> base names
    class_lines: dict[str, int] = field(default_factory=dict)  # class -> line number
    class_info: list[ClassInfo] = field(default_factory=list)  # detailed class data
    defined_functions: set[str] = field(
        default_factory=set
    )  # all func/method names defined
    called_functions: set[str] = field(default_factory=set)  # all func names called
    abstract_classes: set[str] = field(
        default_factory=set
    )  # classes with ABC or abstract methods


# ---------------------------------------------------------------------------
# Detector: walks one file's AST
# ---------------------------------------------------------------------------


class SmellDetector(ast.NodeVisitor):
    def __init__(self, filepath: str, source: str):
        self.filepath = filepath
        self.source = source
        self.source_lines = source.splitlines()
        self.findings: list[Finding] = []

        # State tracking
        self._class_stack: list[ast.ClassDef] = []
        self._func_stack: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        self._class_attrs: dict[str, list[str]] = defaultdict(list)
        self._class_bool_attrs: dict[str, list[str]] = defaultdict(list)
        self._class_methods: dict[str, int] = Counter()
        self._open_calls_outside_with: list[tuple[int, str]] = []
        self._string_concat_lines: set[int] = set()

        # Cross-file data
        self.file_data = FileData(
            filepath=filepath, total_lines=len(source.splitlines())
        )

        # Tier 2/3: class-level collection
        self._current_class_info: ClassInfo | None = None
        self._class_all_fields: dict[str, list[str]] = defaultdict(
            list
        )  # class -> all self.x fields
        self._class_methods_fields: dict[str, dict[str, set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )

    def _add(
        self,
        line: int,
        pattern: str,
        name: str,
        severity: str,
        message: str,
        category: str,
    ):
        rd = _RULE_REGISTRY.get(pattern)
        self.findings.append(
            Finding(
                file=self.filepath,
                line=line,
                pattern=pattern,
                name=name,
                severity=severity,
                message=message,
                category=category,
                scope=rd.scope if rd else "file",
            )
        )

    # =======================================================================
    # State & Immutability
    # =======================================================================

    def _check_setters(self, node: ast.FunctionDef):
        """SC101 -- Remove Setters."""
        if (
            self._class_stack
            and node.name.startswith("set_")
            and len(node.args.args) == 2
        ):
            attr = node.name[4:]
            self._add(
                node.lineno,
                "SC101",
                "Remove Setters",
                "warning",
                f"Setter `{node.name}` -- consider making `{attr}` a constructor param or using @dataclass(frozen=True)",
                "state",
            )

    def _check_half_built_init(self, node: ast.FunctionDef):
        """SC104 -- Build With The Essence: __init__ setting attrs to None."""
        if not (self._class_stack and node.name == "__init__"):
            return
        cls_name = self._class_stack[-1].name
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                        and _is_none(stmt.value)
                    ):
                        self._class_attrs[cls_name].append(target.attr)
            elif isinstance(stmt, ast.AnnAssign):
                if (
                    isinstance(stmt.target, ast.Attribute)
                    and isinstance(stmt.target.value, ast.Name)
                    and stmt.target.value.id == "self"
                    and stmt.value is not None
                    and _is_none(stmt.value)
                ):
                    self._class_attrs[cls_name].append(stmt.target.attr)

    def _check_bool_flag_attrs(self, node: ast.FunctionDef):
        """SC105 -- Convert Attributes to Sets: multiple is_* booleans."""
        if not (self._class_stack and node.name == "__init__"):
            return
        cls_name = self._class_stack[-1].name
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                        and target.attr.startswith("is_")
                        and isinstance(stmt.value, ast.Constant)
                        and isinstance(stmt.value.value, bool)
                    ):
                        self._class_bool_attrs[cls_name].append(target.attr)

    def _check_public_attrs(self, node: ast.FunctionDef):
        """SC103 -- Protect Public Attributes."""
        if not (self._class_stack and node.name == "__init__"):
            return
        public_attrs = []
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                        and not target.attr.startswith("_")
                    ):
                        public_attrs.append(target.attr)
        if len(public_attrs) >= 3:
            self._add(
                node.lineno,
                "SC103",
                "Protect Public Attributes",
                "info",
                f"Class `{self._class_stack[-1].name}` exposes {len(public_attrs)} public attrs: "
                f"{', '.join(public_attrs[:5])}{'...' if len(public_attrs) > 5 else ''}",
                "state",
            )

    # =======================================================================
    # Functions & Methods
    # =======================================================================

    def _check_long_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """SC201 -- Extract Method: function too long."""
        lines = _lines_of(node)
        if lines > MAX_FUNCTION_LINES:
            self._add(
                node.lineno,
                "SC201",
                "Extract Method",
                "warning",
                f"`{node.name}` is {lines} lines (threshold: {MAX_FUNCTION_LINES})",
                "functions",
            )

    def _check_deep_nesting(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """SC402 -- Guard Clauses: deep nesting."""
        depth = _nesting_depth(node)
        if depth > MAX_NESTING_DEPTH:
            self._add(
                node.lineno,
                "SC402",
                "Replace Nested Conditional with Guard Clauses",
                "warning",
                f"`{node.name}` has nesting depth {depth} (threshold: {MAX_NESTING_DEPTH})",
                "control",
            )

    def _check_too_many_params(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """SC206 -- Reify Parameters: long parameter list."""
        args = node.args
        count = len(args.args) + len(args.posonlyargs) + len(args.kwonlyargs)
        if self._class_stack and args.args and args.args[0].arg in ("self", "cls"):
            count -= 1
        if count > MAX_PARAMS:
            self._add(
                node.lineno,
                "SC206",
                "Reify Parameters",
                "warning",
                f"`{node.name}` has {count} parameters (threshold: {MAX_PARAMS})",
                "functions",
            )

    def _check_generic_names(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """SC202 -- Rename Result Variables: generic names."""
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for name in _get_assigned_names(child.targets):
                    if name in GENERIC_NAMES:
                        self._add(
                            child.lineno,
                            "SC202",
                            "Rename Result Variables",
                            "info",
                            f"Generic variable name `{name}` in `{node.name}` -- use a descriptive name",
                            "functions",
                        )

    def _check_cqs_violation(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """SC207 -- Separate Query from Modifier (CQS)."""
        if node.name.startswith("_") or not self._class_stack:
            return
        has_self_assignment = False
        has_return_value = False
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for t in child.targets:
                    if (
                        isinstance(t, ast.Attribute)
                        and isinstance(t.value, ast.Name)
                        and t.value.id == "self"
                    ):
                        has_self_assignment = True
            if (
                isinstance(child, ast.Return)
                and child.value is not None
                and not _is_none(child.value)
            ):
                has_return_value = True
        if has_self_assignment and has_return_value:
            self._add(
                node.lineno,
                "SC207",
                "Separate Query from Modifier",
                "info",
                f"`{node.name}` both mutates self and returns a value -- consider splitting",
                "functions",
            )

    def _check_excessive_decorators(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """SC205 -- Strip Annotations: too many decorators."""
        if len(node.decorator_list) > MAX_DECORATORS:
            self._add(
                node.lineno,
                "SC205",
                "Strip Annotations",
                "info",
                f"`{node.name}` has {len(node.decorator_list)} decorators (threshold: {MAX_DECORATORS})",
                "hygiene",
            )

    def _check_unused_params(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """SC208 -- Remove Unused Parameters."""
        if _is_stub_body(node.body):
            return
        if _has_decorator(node, {"abstractmethod", "override", "overload"}):
            return
        # Collect parameter names
        params: set[str] = set()
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            params.add(arg.arg)
        params -= {"self", "cls"}
        if node.args.vararg:
            params.discard(node.args.vararg.arg)
        if node.args.kwarg:
            params.discard(node.args.kwarg.arg)
        if not params:
            return
        # Collect all names used in body (skip docstring)
        used_names: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                used_names.add(child.id)
        # Parameter names appear as ast.arg, not ast.Name, in the signature
        # but ARE ast.Name when referenced in the body
        unused = params - used_names
        # Also skip _-prefixed params (convention for intentionally unused)
        unused = {p for p in unused if not p.startswith("_")}
        if unused:
            self._add(
                node.lineno,
                "SC208",
                "Remove Unused Parameters",
                "warning",
                f"`{node.name}` has unused parameters: {', '.join(sorted(unused))}",
                "functions",
            )

    def _check_long_lambda(self, node: ast.Lambda):
        """SC209 -- Replace Long Lambda with Function."""
        try:
            source = ast.unparse(node)
        except Exception:
            return
        if len(source) > MAX_LAMBDA_LENGTH:
            self._add(
                node.lineno,
                "SC209",
                "Replace Long Lambda with Function",
                "info",
                f"Lambda is {len(source)} chars (threshold: {MAX_LAMBDA_LENGTH}) -- use a named function",
                "functions",
            )

    # =======================================================================
    # Type Design
    # =======================================================================

    def _check_isinstance_chain(self, node: ast.If):
        """SC302 -- Replace IF with Polymorphism."""
        isinstance_count = 0
        current: ast.AST | None = node
        while current is not None:
            if isinstance(current, ast.If):
                test = current.test
                if (
                    isinstance(test, ast.Call)
                    and isinstance(test.func, ast.Name)
                    and test.func.id == "isinstance"
                ):
                    isinstance_count += 1
                current = (
                    current.orelse[0]
                    if (current.orelse and isinstance(current.orelse[0], ast.If))
                    else None
                )
            else:
                break
        if isinstance_count >= 2:
            self._add(
                node.lineno,
                "SC302",
                "Replace IF with Polymorphism",
                "warning",
                f"isinstance chain with {isinstance_count} branches -- consider polymorphism or Protocol",
                "types",
            )

    def _check_lazy_class(self, node: ast.ClassDef):
        """SC306 -- Remove Lazy Class: class too small to justify existence."""
        # Skip special base classes
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id in (
                "ABC",
                "Protocol",
                "Exception",
                "Enum",
                "IntEnum",
                "StrEnum",
                "TypedDict",
                "NamedTuple",
            ):
                return
            if isinstance(base, ast.Attribute) and base.attr in (
                "ABC",
                "Protocol",
                "Exception",
            ):
                return
        if _has_decorator(node, {"dataclass", "dataclasses"}):
            return
        # Count methods and fields
        method_count = 0
        non_dunder_count = 0
        field_count = 0
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_count += 1
                if not stmt.name.startswith("__"):
                    non_dunder_count += 1
                if stmt.name == "__init__":
                    for child in ast.walk(stmt):
                        if (
                            isinstance(child, ast.Attribute)
                            and isinstance(child.value, ast.Name)
                            and child.value.id == "self"
                            and isinstance(child.ctx, ast.Store)
                        ):
                            field_count += 1
        # A class is lazy if it has very few methods and fields
        if (
            non_dunder_count < MIN_LAZY_CLASS_METHODS
            and field_count < 2
            and method_count > 0
        ):
            self._add(
                node.lineno,
                "SC306",
                "Remove Lazy Class",
                "info",
                f"Class `{node.name}` has {non_dunder_count} non-dunder methods and {field_count} fields "
                f"-- consider inlining or merging",
                "types",
            )

    def _check_temporary_fields(self, node: ast.ClassDef):
        """SC307 -- Remove Temporary Field: fields used in few methods."""
        init_fields: set[str] = set()
        methods: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        for stmt in node.body:
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if stmt.name == "__init__":
                for child in ast.walk(stmt):
                    if (
                        isinstance(child, ast.Attribute)
                        and isinstance(child.value, ast.Name)
                        and child.value.id == "self"
                        and isinstance(child.ctx, ast.Store)
                    ):
                        init_fields.add(child.attr)
            elif not stmt.name.startswith("__"):
                methods.append(stmt)

        if not init_fields or len(methods) < 3:
            return

        for field_name in init_fields:
            usage_count = 0
            for method in methods:
                for child in ast.walk(method):
                    if (
                        isinstance(child, ast.Attribute)
                        and isinstance(child.value, ast.Name)
                        and child.value.id == "self"
                        and child.attr == field_name
                    ):
                        usage_count += 1
                        break
            ratio = usage_count / len(methods)
            if ratio < TEMP_FIELD_USAGE_RATIO:
                self._add(
                    node.lineno,
                    "SC307",
                    "Remove Temporary Field",
                    "info",
                    f"`{node.name}.{field_name}` used in {usage_count}/{len(methods)} methods "
                    f"({ratio:.0%}) -- consider local variable or parameter",
                    "types",
                )

    # =======================================================================
    # Control Flow
    # =======================================================================

    def _check_loop_append(self, node: ast.For | ast.While):
        """SC403 -- Replace Loop with Pipeline."""
        for stmt in ast.walk(node):
            if (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Call)
                and isinstance(stmt.value.func, ast.Attribute)
                and stmt.value.func.attr == "append"
            ):
                self._add(
                    node.lineno,
                    "SC403",
                    "Replace Loop with Pipeline",
                    "info",
                    "Loop with `.append()` -- consider list comprehension or generator",
                    "control",
                )
                return

    def _check_control_flag(self, node: ast.For | ast.While):
        """SC405 -- Replace Control Flag with Break."""
        parent_body = None
        if self._func_stack:
            parent_body = self._func_stack[-1].body
        if parent_body is None:
            return

        flag_names = set()
        for stmt in parent_body:
            if stmt is node:
                break
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and isinstance(stmt.value, ast.Constant)
                and stmt.value.value is False
            ):
                flag_names.add(stmt.targets[0].id)

        if not flag_names:
            return

        for child in ast.walk(node):
            if isinstance(child, ast.If):
                test = child.test
                if isinstance(test, ast.Name) and test.id in flag_names:
                    self._add(
                        node.lineno,
                        "SC405",
                        "Replace Control Flag with Break",
                        "info",
                        f"Boolean flag `{test.id}` controls loop -- use `break`/`return`/`any()`",
                        "control",
                    )
                    return
                if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                    if (
                        isinstance(test.operand, ast.Name)
                        and test.operand.id in flag_names
                    ):
                        self._add(
                            node.lineno,
                            "SC405",
                            "Replace Control Flag with Break",
                            "info",
                            f"Boolean flag `{test.operand.id}` controls loop -- use `break`/`return`/`any()`",
                            "control",
                        )
                        return

    def _check_complex_boolean(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """SC404 -- Decompose Conditional."""

        def _count_bool_ops(expr: ast.AST) -> int:
            if isinstance(expr, ast.BoolOp):
                count = len(expr.values) - 1
                for v in expr.values:
                    count += _count_bool_ops(v)
                return count
            return 0

        for child in ast.walk(node):
            if isinstance(child, ast.If):
                ops = _count_bool_ops(child.test)
                if ops >= 3:
                    self._add(
                        child.lineno,
                        "SC404",
                        "Decompose Conditional",
                        "warning",
                        f"Complex boolean ({ops} operators) in `{node.name}` -- extract to descriptive function",
                        "control",
                    )
                    return

    def _check_missing_else(self, node: ast.If):
        """SC407 -- Add Default Else Branch: if/elif chain without else."""
        # Only flag top-level if statements (not nested inside elif)
        has_elif = False
        current = node
        branch_count = 1
        while current.orelse:
            if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
                has_elif = True
                branch_count += 1
                current = current.orelse[0]
            else:
                return  # has an else clause -- fine
        if has_elif and branch_count >= 2:
            self._add(
                node.lineno,
                "SC407",
                "Add Default Else Branch",
                "info",
                f"if/elif chain with {branch_count} branches but no default `else`",
                "control",
            )

    def _check_long_comprehension(self, node: ast.AST):
        """SC406 -- Simplify Complex Comprehension: too many nested generators."""
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            if len(node.generators) > MAX_COMPREHENSION_GENERATORS:
                kind = {
                    ast.ListComp: "List comprehension",
                    ast.SetComp: "Set comprehension",
                    ast.GeneratorExp: "Generator expression",
                }.get(type(node), "Comprehension")
                self._add(
                    node.lineno,
                    "SC406",
                    "Simplify Complex Comprehension",
                    "info",
                    f"{kind} has {len(node.generators)} nested loops -- simplify or use explicit loops",
                    "control",
                )
        elif isinstance(node, ast.DictComp):
            if len(node.generators) > MAX_COMPREHENSION_GENERATORS:
                self._add(
                    node.lineno,
                    "SC406",
                    "Simplify Complex Comprehension",
                    "info",
                    f"Dict comprehension has {len(node.generators)} nested loops -- simplify",
                    "control",
                )

    # =======================================================================
    # Architecture
    # =======================================================================

    def _check_singleton(self, node: ast.ClassDef):
        """SC303 -- Replace Singleton."""
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    if (
                        isinstance(t, ast.Name)
                        and t.id == "_instance"
                        and _is_none(stmt.value)
                    ):
                        self._add(
                            node.lineno,
                            "SC303",
                            "Replace Singleton",
                            "warning",
                            f"Class `{node.name}` uses Singleton pattern -- consider dependency injection",
                            "architecture",
                        )
                        return

    def _check_global_mutable(self, node: ast.Assign):
        """SC106 -- Replace Global Variables with DI."""
        if self._class_stack or self._func_stack:
            return
        if isinstance(node.value, (ast.Call, ast.Dict, ast.List, ast.Set)):
            for name in _get_assigned_names(node.targets):
                if not name.startswith("_") and name != name.upper():
                    self._add(
                        node.lineno,
                        "SC106",
                        "Replace Global Variables with DI",
                        "info",
                        f"Module-level mutable `{name}` -- consider dependency injection",
                        "architecture",
                    )

    def _check_constant_without_final(self, node: ast.Assign):
        """SC102 -- Convert Variables to Constants."""
        if self._class_stack or self._func_stack:
            return
        for name in _get_assigned_names(node.targets):
            if name == name.upper() and name.startswith(
                tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            ):
                self._add(
                    node.lineno,
                    "SC102",
                    "Convert Variables to Constants",
                    "info",
                    f"`{name}` is UPPER_CASE but not annotated with `typing.Final`",
                    "state",
                )

    def _check_sequential_ids(self, node: ast.ClassDef):
        """SC107 -- Replace Sequential IDs."""
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    if isinstance(t, ast.Name) and re.match(
                        r"^_?(counter|next_id|id_counter|sequence|seq_num|auto_increment)",
                        t.id,
                        re.IGNORECASE,
                    ):
                        self._add(
                            node.lineno,
                            "SC107",
                            "Replace Sequential IDs",
                            "info",
                            f"Class `{node.name}` uses sequential ID pattern (`{t.id}`) -- consider UUID",
                            "architecture",
                        )
                        return

    def _check_error_codes(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """SC501 -- Replace Error Codes with Exceptions."""
        return_ints: set[int] = set()
        total_returns = 0
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value is not None:
                total_returns += 1
                if isinstance(child.value, ast.Constant) and isinstance(
                    child.value.value, int
                ):
                    if isinstance(child.value.value, bool):
                        continue
                    return_ints.add(child.value.value)
                elif isinstance(child.value, ast.UnaryOp) and isinstance(
                    child.value.op, ast.USub
                ):
                    if isinstance(child.value.operand, ast.Constant) and isinstance(
                        child.value.operand.value, int
                    ):
                        return_ints.add(-child.value.operand.value)
        if len(return_ints) >= 2 and total_returns >= 2:
            if return_ints.issubset({-1, 0, 1, -2, 2}):
                self._add(
                    node.lineno,
                    "SC501",
                    "Replace Error Codes with Exceptions",
                    "warning",
                    f"`{node.name}` returns status codes {sorted(return_ints)} -- use exceptions",
                    "architecture",
                )

    def _check_law_of_demeter(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """SC502 -- Law of Demeter: chained .attr.attr.attr access."""
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                depth = 1
                current = child.value
                while isinstance(current, ast.Attribute):
                    depth += 1
                    current = current.value
                if (
                    depth >= 3
                    and isinstance(current, ast.Name)
                    and current.id != "self"
                ):
                    parts = [child.attr]
                    inner = child.value
                    while isinstance(inner, ast.Attribute):
                        parts.append(inner.attr)
                        inner = inner.value
                    if isinstance(inner, ast.Name):
                        parts.append(inner.id)
                    chain = ".".join(reversed(parts))
                    self._add(
                        child.lineno,
                        "SC502",
                        "Law of Demeter",
                        "info",
                        f"Chain `{chain}` ({depth + 1} deep) in `{node.name}` -- introduce a delegate",
                        "architecture",
                    )
                    return

    # =======================================================================
    # Hygiene
    # =======================================================================

    def _check_bare_except(self, node: ast.ExceptHandler):
        """SC602 -- Remove Unhandled Exceptions."""
        is_bare = node.type is None
        is_broad = isinstance(node.type, ast.Name) and node.type.id == "Exception"
        body_is_pass = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)

        if is_bare:
            self._add(
                node.lineno,
                "SC602",
                "Remove Unhandled Exceptions",
                "error",
                "Bare `except:` -- always catch specific exceptions",
                "hygiene",
            )
        elif is_broad and body_is_pass:
            self._add(
                node.lineno,
                "SC602",
                "Remove Unhandled Exceptions",
                "warning",
                "`except Exception: pass` -- silently swallowing all errors",
                "hygiene",
            )

    def _check_empty_catch(self, node: ast.ExceptHandler):
        """SC605 -- Remove Empty Catch Block: except SomeError: pass."""
        # Skip cases already handled by SC602 (bare except, except Exception: pass)
        if node.type is None:
            return
        if isinstance(node.type, ast.Name) and node.type.id == "Exception":
            return
        body_is_pass = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
        if body_is_pass and node.type is not None:
            exc_name = ""
            if isinstance(node.type, ast.Name):
                exc_name = node.type.id
            elif isinstance(node.type, ast.Attribute):
                exc_name = node.type.attr
            else:
                exc_name = ast.dump(node.type)
            self._add(
                node.lineno,
                "SC605",
                "Remove Empty Catch Block",
                "warning",
                f"`except {exc_name}: pass` -- silently swallowing `{exc_name}`",
                "hygiene",
            )

    def _check_magic_numbers(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """SC601 -- Extract Constant: magic numbers."""
        return_lines = set()
        default_nodes: set[int] = set()
        for d in node.args.defaults + node.args.kw_defaults:
            if d is not None:
                default_nodes.add(id(d))
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and isinstance(
                getattr(child, "value", None), ast.Constant
            ):
                return_lines.add(child.lineno)

        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(
                child.value, (int, float)
            ):
                if child.value in MAGIC_NUMBER_WHITELIST:
                    continue
                if id(child) in default_nodes:
                    continue
                if child.lineno in return_lines:
                    continue
                if isinstance(child.value, int) and -10 <= child.value <= 10:
                    continue
                self._add(
                    child.lineno,
                    "SC601",
                    "Extract Constant",
                    "info",
                    f"Magic number `{child.value}` -- extract to a named constant",
                    "hygiene",
                )

    def _check_string_concat(self, node: ast.BinOp):
        """SC603 -- Replace String Concatenation."""
        if not isinstance(node.op, ast.Add):
            return
        if node.lineno in self._string_concat_lines:
            return
        parts = 0
        current: ast.AST = node
        while isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            parts += 1
            current = current.left
        if parts >= 3:
            self._string_concat_lines.add(node.lineno)
            self._add(
                node.lineno,
                "SC603",
                "Replace String Concatenation",
                "info",
                "Multiple string concatenations -- consider f-string or triple-quoted string",
                "hygiene",
            )

    # =======================================================================
    # Python Idioms
    # =======================================================================

    def _check_mutable_default(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """SC701 -- Replace Mutable Default Arguments."""
        for default in node.args.defaults + node.args.kw_defaults:
            if default is not None and _is_mutable_literal(default):
                self._add(
                    node.lineno,
                    "SC701",
                    "Replace Mutable Default Arguments",
                    "error",
                    f"`{node.name}` has mutable default argument -- use `None` sentinel",
                    "idioms",
                )

    def _check_open_without_with(self, node: ast.Call):
        """SC702 -- Use Context Managers."""
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            self._open_calls_outside_with.append((node.lineno, "open"))

    def _check_blocking_in_async(self, node: ast.AsyncFunctionDef):
        """SC703 -- Avoid Blocking Calls in Async Functions."""
        for child in _walk_skip_nested_scopes(node):
            if not isinstance(child, ast.Call):
                continue
            # Skip calls wrapped in asyncio.to_thread() or loop.run_in_executor()
            if self._is_offloaded_call(child, node):
                continue
            key = _get_blocking_call_key(child)
            if key is not None:
                display, alt = _BLOCKING_CALLS[key]
                self._add(
                    child.lineno,
                    "SC703",
                    "Avoid Blocking Calls in Async Functions",
                    "warning",
                    f"`{display}` blocks the event loop in async function `{node.name}` -- use {alt}",
                    "idioms",
                )

    @staticmethod
    def _is_offloaded_call(call_node: ast.Call, async_func: ast.AsyncFunctionDef) -> bool:
        """Return True if *call_node* is wrapped by ``to_thread()`` or ``run_in_executor()``."""
        for wrapper in _walk_skip_nested_scopes(async_func):
            if not isinstance(wrapper, ast.Call):
                continue
            if _is_to_thread_call(wrapper) or _is_run_in_executor_call(wrapper):
                if call_node in wrapper.args:
                    return True
                if call_node in (kw.value for kw in wrapper.keywords):
                    return True
        return False

    def _check_cyclomatic_complexity(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ):
        """Cyclomatic Complexity check."""
        cc = _cyclomatic_complexity(node)
        if cc > MAX_CYCLOMATIC_COMPLEXITY:
            self._add(
                node.lineno,
                "SC210",
                "Reduce Cyclomatic Complexity",
                "warning",
                f"`{node.name}` has CC={cc} (threshold: {MAX_CYCLOMATIC_COMPLEXITY}) -- split into smaller functions",
                "functions",
            )

    def _check_index_access(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """SC305 -- Use Unpacking Instead of Indexing."""
        index_accesses: dict[str, list[int]] = defaultdict(list)
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Subscript)
                and isinstance(child.value, ast.Name)
                and isinstance(child.slice, ast.Constant)
                and isinstance(child.slice.value, int)
            ):
                index_accesses[child.value.id].append(child.slice.value)
        for var_name, indices in index_accesses.items():
            unique = sorted(set(indices))
            if len(unique) >= 3 and unique[:3] == [0, 1, 2]:
                self._add(
                    node.lineno,
                    "SC305",
                    "Use Unpacking Instead of Indexing",
                    "info",
                    f"`{var_name}[0]`, `{var_name}[1]`, `{var_name}[2]`... in `{node.name}` -- use unpacking",
                    "idioms",
                )

    def _check_return_none_or_value(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """SC204 -- Replace NULL with Collection."""
        returns_none = False
        returns_value = False
        for child in ast.walk(node):
            if isinstance(child, ast.Return):
                if child.value is None or _is_none(child.value):
                    returns_none = True
                elif isinstance(
                    child.value, (ast.List, ast.ListComp, ast.GeneratorExp)
                ):
                    returns_value = True
                else:
                    returns_value = True
        if returns_none and returns_value:
            for child in ast.walk(node):
                if (
                    isinstance(child, ast.Return)
                    and child.value is not None
                    and isinstance(child.value, (ast.List, ast.ListComp))
                ):
                    self._add(
                        node.lineno,
                        "SC204",
                        "Replace NULL with Collection",
                        "info",
                        f"`{node.name}` returns both None and a list -- always return empty list",
                        "types",
                    )
                    return

    def _check_dead_code_after_return(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ):
        """SC401 -- Remove Dead Code."""
        terminal = (ast.Return, ast.Raise, ast.Break, ast.Continue)

        def _check_body(body: list[ast.stmt]):
            for i, stmt in enumerate(body):
                if isinstance(stmt, terminal) and i < len(body) - 1:
                    next_stmt = body[i + 1]
                    self._add(
                        next_stmt.lineno,
                        "SC401",
                        "Remove Dead Code",
                        "warning",
                        f"Unreachable code after `{type(stmt).__name__.lower()}` in `{node.name}`",
                        "hygiene",
                    )
                    return
                if isinstance(stmt, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                    for attr in ("body", "orelse", "finalbody", "handlers"):
                        sub = getattr(stmt, attr, None)
                        if isinstance(sub, list):
                            if attr == "handlers":
                                for handler in sub:
                                    if isinstance(handler, ast.ExceptHandler):
                                        _check_body(handler.body)
                            else:
                                _check_body(sub)

        _check_body(node.body)

    def _check_input_in_logic(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """SC203 -- Replace input() Calls."""
        if node.name in ("main", "__main__", "cli", "repl", "prompt", "interactive"):
            return
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id == "input"
            ):
                self._add(
                    child.lineno,
                    "SC203",
                    "Replace input() Calls",
                    "warning",
                    f"`input()` in `{node.name}` -- inject data via parameters",
                    "functions",
                )
                return

    def _check_dataclass_candidate(self, node: ast.ClassDef):
        """SC304 -- Replace Class with Dataclass."""
        method_names = set()
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_names.add(stmt.name)
        if _has_decorator(node, {"dataclass", "dataclasses"}):
            return
        boilerplate = method_names & {
            "__init__",
            "__repr__",
            "__eq__",
            "__hash__",
            "__str__",
        }
        if len(boilerplate) >= 2:
            self._add(
                node.lineno,
                "SC304",
                "Replace Class with Dataclass",
                "info",
                f"Class `{node.name}` implements {', '.join(sorted(boilerplate))} -- consider @dataclass",
                "idioms",
            )

    def _check_context_manager_class(self, node: ast.ClassDef):
        """SC604 -- Replace with contextlib."""
        method_names = set()
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_names.add(stmt.name)
        if "__enter__" in method_names and "__exit__" in method_names:
            real_methods = {
                m for m in method_names if not m.startswith("__") or m in ("__init__",)
            }
            if len(real_methods) <= 2:
                self._add(
                    node.lineno,
                    "SC604",
                    "Replace with contextlib",
                    "info",
                    f"Class `{node.name}` implements __enter__/__exit__ -- consider @contextmanager",
                    "idioms",
                )

    # =======================================================================
    # Data collection for cross-file analysis (Tier 2/3)
    # =======================================================================

    def _collect_func_data(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """Collect function signature data for duplicate detection."""
        lines = _lines_of(node)
        if lines < MIN_DUPLICATE_LINES:
            return
        norm = _normalize_ast(node)
        sig_hash = hashlib.md5(norm.encode()).hexdigest()[:HASH_PREFIX_LEN]
        self.file_data.func_signatures.append(
            (self.filepath, node.name, node.lineno, sig_hash, lines)
        )

    def _collect_external_accesses(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """Collect external attribute accesses for feature-envy detection."""
        if not self._class_stack:
            return
        accesses: dict[str, int] = Counter()
        self_accesses = 0
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
                if child.value.id == "self":
                    self_accesses += 1
                elif child.value.id[0].isupper():
                    accesses[child.value.id] += 1
        for cls_name, count in accesses.items():
            if count >= FEATURE_ENVY_THRESHOLD and count > self_accesses:
                self.file_data.method_external_accesses.append(
                    (
                        node.name,
                        node.lineno,
                        self._class_stack[-1].name,
                        {cls_name: count},
                    )
                )

    def _collect_defined_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """Track function definitions for shotgun surgery detection."""
        self.file_data.defined_functions.add(node.name)

    def _collect_called_functions(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        """Track function calls for shotgun surgery and RFC detection."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    self.file_data.called_functions.add(child.func.id)
                elif isinstance(child.func, ast.Attribute):
                    self.file_data.called_functions.add(child.func.attr)

    def _collect_class_info(self, node: ast.ClassDef):
        """Collect detailed class information for Tier 2/3 analysis."""
        bases = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                bases.append(base.id)
            elif isinstance(base, ast.Attribute):
                bases.append(base.attr)

        self.file_data.class_bases[node.name] = bases
        self.file_data.class_lines[node.name] = node.lineno

        ci = ClassInfo(
            name=node.name, filepath=self.filepath, line=node.lineno, bases=bases
        )

        # Check for abstract methods and ABC base
        is_abstract = "ABC" in bases or "ABCMeta" in bases
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ci.method_count += 1
                if not stmt.name.startswith("__"):
                    ci.non_dunder_method_count += 1
                if _has_decorator(stmt, {"abstractmethod"}):
                    ci.abstract_methods.append(stmt.name)
                    is_abstract = True

                # Collect fields accessed by this method
                fields_accessed: set[str] = set()
                for child in ast.walk(stmt):
                    if (
                        isinstance(child, ast.Attribute)
                        and isinstance(child.value, ast.Name)
                        and child.value.id == "self"
                    ):
                        fields_accessed.add(child.attr)
                ci.methods_using_fields[stmt.name] = fields_accessed

                # Collect init fields
                if stmt.name == "__init__":
                    for child in ast.walk(stmt):
                        if (
                            isinstance(child, ast.Attribute)
                            and isinstance(child.value, ast.Name)
                            and child.value.id == "self"
                            and isinstance(child.ctx, ast.Store)
                        ):
                            ci.all_fields.append(child.attr)
                            ci.field_count += 1

                # Detect delegation methods (body is just return self.x.method(...))
                if len(stmt.body) == 1:
                    s = stmt.body[0]
                    if isinstance(s, ast.Return) and isinstance(s.value, ast.Call):
                        func = s.value.func
                        if (
                            isinstance(func, ast.Attribute)
                            and isinstance(func.value, ast.Attribute)
                            and isinstance(func.value.value, ast.Name)
                            and func.value.value.id == "self"
                        ):
                            ci.delegation_count += 1
                    elif isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
                        func = s.value.func
                        if (
                            isinstance(func, ast.Attribute)
                            and isinstance(func.value, ast.Attribute)
                            and isinstance(func.value.value, ast.Name)
                            and func.value.value.id == "self"
                        ):
                            ci.delegation_count += 1

        # Collect external class accesses for intimacy/CBO and external method calls for RFC
        ext_accesses: dict[str, int] = Counter()
        ext_method_calls: set[str] = set()
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(stmt):
                    if isinstance(child, ast.Attribute) and isinstance(
                        child.value, ast.Name
                    ):
                        if child.value.id != "self" and child.value.id[0:1].isupper():
                            ext_accesses[child.value.id] += 1
                    # Track distinct external method calls: self.x.method() and ClassName.method()
                    if isinstance(child, ast.Call) and isinstance(
                        child.func, ast.Attribute
                    ):
                        receiver = child.func.value
                        method_name = child.func.attr
                        if isinstance(receiver, ast.Name) and receiver.id != "self":
                            ext_method_calls.add(f"{receiver.id}.{method_name}")
                        elif (
                            isinstance(receiver, ast.Attribute)
                            and isinstance(receiver.value, ast.Name)
                            and receiver.value.id == "self"
                        ):
                            ext_method_calls.add(f"self.{receiver.attr}.{method_name}")
        ci.external_class_accesses = dict(ext_accesses)
        ci.external_method_calls = ext_method_calls
        ci.is_abstract = is_abstract

        if is_abstract:
            self.file_data.abstract_classes.add(node.name)

        self.file_data.class_info.append(ci)

    # =======================================================================
    # Visitors
    # =======================================================================

    def visit_ClassDef(self, node: ast.ClassDef):
        if not self._class_stack and not self._func_stack:
            self.file_data.toplevel_defs += 1
            self.file_data.class_names.append(node.name)

        self._class_stack.append(node)
        self._check_singleton(node)
        self._check_sequential_ids(node)
        self._check_dataclass_candidate(node)
        self._check_context_manager_class(node)
        self._check_lazy_class(node)
        self._check_temporary_fields(node)
        self._collect_class_info(node)
        self.generic_visit(node)
        self._class_stack.pop()

        # Post-class checks
        cls_name = node.name
        none_attrs = self._class_attrs.get(cls_name, [])
        if len(none_attrs) >= 2:
            self._add(
                node.lineno,
                "SC104",
                "Build With The Essence",
                "warning",
                f"`{cls_name}.__init__` sets {len(none_attrs)} attrs to None: "
                f"{', '.join(none_attrs[:5])} -- require them in constructor",
                "state",
            )

        bool_attrs = self._class_bool_attrs.get(cls_name, [])
        if len(bool_attrs) >= 3:
            self._add(
                node.lineno,
                "SC105",
                "Convert Attributes to Sets",
                "info",
                f"`{cls_name}` has {len(bool_attrs)} boolean flags: "
                f"{', '.join(bool_attrs)} -- consider a roles/tags set",
                "state",
            )

        method_count = self._class_methods.get(cls_name, 0)
        if method_count > MAX_CLASS_METHODS:
            self._add(
                node.lineno,
                "SC301",
                "Extract Class",
                "info",
                f"`{cls_name}` has {method_count} methods -- consider splitting",
                "types",
            )

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._visit_func(node)

    def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        if self._class_stack:
            self._class_methods[self._class_stack[-1].name] += 1
        if not self._class_stack and not self._func_stack:
            self.file_data.toplevel_defs += 1

        self._func_stack.append(node)

        # All function-level checks
        self._check_setters(node)
        self._check_half_built_init(node)
        self._check_bool_flag_attrs(node)
        self._check_public_attrs(node)
        self._check_long_function(node)
        self._check_deep_nesting(node)
        self._check_too_many_params(node)
        self._check_mutable_default(node)
        self._check_excessive_decorators(node)
        self._check_generic_names(node)
        self._check_cqs_violation(node)
        self._check_magic_numbers(node)
        self._check_return_none_or_value(node)
        self._check_dead_code_after_return(node)
        self._check_input_in_logic(node)
        self._check_error_codes(node)
        self._check_law_of_demeter(node)
        self._check_complex_boolean(node)
        self._check_index_access(node)
        self._check_cyclomatic_complexity(node)
        self._check_unused_params(node)
        if isinstance(node, ast.AsyncFunctionDef):
            self._check_blocking_in_async(node)
        # Data collection
        self._collect_func_data(node)
        self._collect_external_accesses(node)
        self._collect_defined_function(node)
        self._collect_called_functions(node)

        self.generic_visit(node)
        self._func_stack.pop()

    def visit_If(self, node: ast.If):
        # Skip elif branches -- they are ast.If nodes nested in orelse of the parent If.
        # Only check top-level If nodes to avoid duplicate findings (#014, #068).
        if not self._is_elif(node):
            self._check_isinstance_chain(node)
            self._check_missing_else(node)
        self.generic_visit(node)

    def _is_elif(self, node: ast.If) -> bool:
        """Check if this If node is an elif (nested inside another If's orelse)."""
        # Walk up through the parent chain by checking func/class bodies
        # Since ast doesn't track parents, we check the enclosing scope's body
        scope = self._func_stack[-1] if self._func_stack else None
        if scope is None:
            return False
        for parent in ast.walk(scope):
            if isinstance(parent, ast.If) and parent is not node:
                if len(parent.orelse) == 1 and parent.orelse[0] is node:
                    return True
        return False

    def visit_For(self, node: ast.For):
        self._check_loop_append(node)
        self._check_control_flag(node)
        self.generic_visit(node)

    def visit_While(self, node: ast.While):
        self._check_loop_append(node)
        self._check_control_flag(node)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        self._check_bare_except(node)
        self._check_empty_catch(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        self._check_global_mutable(node)
        self._check_constant_without_final(node)
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        self._check_string_concat(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        self._check_open_without_with(node)
        self.generic_visit(node)

    def visit_Lambda(self, node: ast.Lambda):
        self._check_long_lambda(node)
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp):
        self._check_long_comprehension(node)
        self.generic_visit(node)

    def visit_SetComp(self, node: ast.SetComp):
        self._check_long_comprehension(node)
        self.generic_visit(node)

    def visit_DictComp(self, node: ast.DictComp):
        self._check_long_comprehension(node)
        self.generic_visit(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp):
        self._check_long_comprehension(node)
        self.generic_visit(node)

    def visit_With(self, node: ast.With):
        safe_open_lines: set[int] = set()
        for item in node.items:
            ctx = item.context_expr
            if isinstance(ctx, ast.Call):
                if isinstance(ctx.func, ast.Name) and ctx.func.id == "open":
                    safe_open_lines.add(ctx.lineno)
                elif isinstance(ctx.func, ast.Attribute) and ctx.func.attr == "open":
                    safe_open_lines.add(ctx.lineno)
        # Also clear open() calls wrapped in ExitStack.enter_context(open(...))
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "enter_context"
            ):
                for arg in child.args:
                    if (
                        isinstance(arg, ast.Call)
                        and isinstance(arg.func, ast.Name)
                        and arg.func.id == "open"
                    ):
                        safe_open_lines.add(arg.lineno)
        self.generic_visit(node)
        self._open_calls_outside_with = [
            (line, name)
            for line, name in self._open_calls_outside_with
            if line not in safe_open_lines
        ]

    def finalize(self):
        """Post-traversal checks."""
        for line, name in self._open_calls_outside_with:
            self._add(
                line,
                "SC702",
                "Use Context Managers",
                "warning",
                f"`{name}()` call without `with` statement -- use context manager",
                "idioms",
            )


# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------


def scan_file(
    filepath: Path, *, source: str | None = None,
) -> tuple[list[Finding], FileData | None]:
    """Parse and scan a single Python file.

    When *source* is provided the file is not re-read from disk (used by
    the caching layer which already read the content for hashing).
    """
    if source is None:
        try:
            source = filepath.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            return [], None
    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError:
        return [], None

    detector = SmellDetector(str(filepath), source)
    detector.visit(tree)
    detector.finalize()
    detector.file_data.imports = _extract_imports(tree)
    return detector.findings, detector.file_data


# ---------------------------------------------------------------------------
# Cross-file / metric finding helper
# ---------------------------------------------------------------------------


def _make_finding(
    file: str,
    line: int,
    pattern: str,
    name: str,
    severity: str,
    message: str,
    category: str,
) -> Finding:
    """Create a Finding enriched from the rule registry (cross-file / metric use)."""
    rd = _RULE_REGISTRY.get(pattern)
    return Finding(
        file=file,
        line=line,
        pattern=pattern,
        name=name,
        severity=severity,
        message=message,
        category=category,
        scope=rd.scope if rd else "cross_file",
    )


# ---------------------------------------------------------------------------
# Cross-file analysis (second pass) -- Original patterns
# ---------------------------------------------------------------------------


def _detect_duplicate_functions(all_data: list[FileData]) -> list[Finding]:
    """SC606 -- Structurally identical functions via AST-normalized hashing."""
    hash_groups: dict[str, list[tuple[str, str, int, int]]] = defaultdict(list)
    for fd in all_data:
        for filepath, func_name, line, sig_hash, line_count in fd.func_signatures:
            hash_groups[sig_hash].append((filepath, func_name, line, line_count))

    findings: list[Finding] = []
    for group in hash_groups.values():
        if len(group) < 2:
            continue
        if all(lc < MIN_DUPLICATE_LINES for _, _, _, lc in group):
            continue
        first_file, first_name, first_line, _ = group[0]
        others = [f"{Path(fp).name}:{fn}" for fp, fn, _, _ in group[1:]]
        findings.append(
            _make_finding(
                file=first_file,
                line=first_line,
                pattern="SC606",
                name="Remove Duplicated Code",
                severity="warning",
                message=f"`{first_name}` has structurally identical copies: {', '.join(others)}",
                category="hygiene",
            )
        )
    return findings


def _detect_cyclic_imports(all_data: list[FileData]) -> list[Finding]:
    """SC503 -- Circular imports via DFS on intra-project import graph."""
    module_map = {fd.filepath: Path(fd.filepath).stem for fd in all_data}
    reverse_map: dict[str, str] = {v: k for k, v in module_map.items()}
    import_graph: dict[str, set[str]] = defaultdict(set)
    for fd in all_data:
        src_module = module_map[fd.filepath]
        for imp in fd.imports:
            if imp in reverse_map:
                import_graph[src_module].add(imp)

    visited: set[str] = set()
    in_stack: set[str] = set()
    cycles: list[tuple[str, str]] = []

    def _dfs(node: str, path: list[str]):
        if node in in_stack:
            cycles.append((path[-1], node))
            return
        if node in visited:
            return
        visited.add(node)
        in_stack.add(node)
        path.append(node)
        for neighbor in import_graph.get(node, set()):
            _dfs(neighbor, path)
        path.pop()
        in_stack.discard(node)

    for module in import_graph:
        visited.clear()
        in_stack.clear()
        _dfs(module, [])

    findings: list[Finding] = []
    reported: set[frozenset[str]] = set()
    for a, b in cycles:
        key = frozenset({a, b})
        if key in reported:
            continue
        reported.add(key)
        findings.append(
            _make_finding(
                file=reverse_map.get(a, a),
                line=1,
                pattern="SC503",
                name="Break Cyclic Import",
                severity="warning",
                message=f"Circular import: `{a}` <-> `{b}` -- extract shared types to break cycle",
                category="architecture",
            )
        )
    return findings


def _detect_god_modules(all_data: list[FileData]) -> list[Finding]:
    """SC504 -- Modules with too many top-level definitions."""
    return [
        _make_finding(
            file=fd.filepath,
            line=1,
            pattern="SC504",
            name="Split God Module",
            severity="warning",
            message=f"Module has {fd.toplevel_defs} top-level definitions "
            f"(threshold: {MAX_MODULE_TOPLEVEL_DEFS}) -- split into focused modules",
            category="architecture",
        )
        for fd in all_data
        if fd.toplevel_defs > MAX_MODULE_TOPLEVEL_DEFS
    ]


def _detect_feature_envy(all_data: list[FileData]) -> list[Finding]:
    """SC211 -- Methods that access external class more than their own."""
    project_classes: set[str] = set()
    for fd in all_data:
        project_classes.update(fd.class_names)

    findings: list[Finding] = []
    for fd in all_data:
        for (
            method_name,
            line,
            host_class,
            external_counts,
        ) in fd.method_external_accesses:
            for ext_class, count in external_counts.items():
                if ext_class not in project_classes:
                    continue
                findings.append(
                    _make_finding(
                        file=fd.filepath,
                        line=line,
                        pattern="SC211",
                        name="Move Method (Feature Envy)",
                        severity="info",
                        message=f"`{host_class}.{method_name}` accesses `{ext_class}` "
                        f"{count} times -- consider moving to `{ext_class}`",
                        category="architecture",
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Cross-file analysis (second pass) -- Tier 2: new patterns
# ---------------------------------------------------------------------------


def _detect_shotgun_surgery(all_data: list[FileData]) -> list[Finding]:
    """SC505 -- Function called from too many different files."""
    defined_in: dict[str, list[str]] = defaultdict(list)
    called_from: dict[str, set[str]] = defaultdict(set)

    for fd in all_data:
        for func_name in fd.defined_functions:
            defined_in[func_name].append(fd.filepath)
        for func_name in fd.called_functions:
            called_from[func_name].add(fd.filepath)

    findings: list[Finding] = []
    for func_name, callers in called_from.items():
        if func_name not in defined_in:
            continue
        # Exclude common names
        if func_name in {
            "__init__",
            "__str__",
            "__repr__",
            "main",
            "setup",
            "run",
            "get",
            "set",
            "update",
            "delete",
            "create",
            "log",
            "print",
        }:
            continue
        external_callers = callers - set(defined_in[func_name])
        if len(external_callers) > SHOTGUN_SURGERY_THRESHOLD:
            def_file = defined_in[func_name][0]
            findings.append(
                _make_finding(
                    file=def_file,
                    line=1,
                    pattern="SC505",
                    name="Shotgun Surgery",
                    severity="info",
                    message=f"`{func_name}` is called from {len(external_callers)} different files "
                    f"(threshold: {SHOTGUN_SURGERY_THRESHOLD}) -- changes will cascade widely",
                    category="architecture",
                )
            )
    return findings


def _detect_deep_inheritance(all_data: list[FileData]) -> list[Finding]:
    """SC308 -- Deep inheritance tree."""
    all_bases: dict[str, list[str]] = {}
    all_locations: dict[str, tuple[str, int]] = {}
    for fd in all_data:
        for cls_name, bases in fd.class_bases.items():
            all_bases[cls_name] = bases
            all_locations[cls_name] = (fd.filepath, fd.class_lines.get(cls_name, 1))

    def _depth(cls_name: str, visited: set[str] | None = None) -> int:
        if visited is None:
            visited = set()
        if cls_name in visited or cls_name not in all_bases:
            return 0
        visited.add(cls_name)
        bases = all_bases[cls_name]
        if not bases:
            return 0
        return 1 + max(
            (_depth(b, visited.copy()) for b in bases if b in all_bases), default=0
        )

    findings: list[Finding] = []
    for cls_name in all_bases:
        d = _depth(cls_name)
        if d > MAX_INHERITANCE_DEPTH:
            filepath, line = all_locations[cls_name]
            findings.append(
                _make_finding(
                    file=filepath,
                    line=line,
                    pattern="SC308",
                    name="Deep Inheritance Tree",
                    severity="warning",
                    message=f"Class `{cls_name}` has inheritance depth {d} "
                    f"(threshold: {MAX_INHERITANCE_DEPTH}) -- favor composition",
                    category="types",
                )
            )
    return findings


def _detect_wide_hierarchy(all_data: list[FileData]) -> list[Finding]:
    """SC309 -- Too many direct subclasses."""
    children: dict[str, list[str]] = defaultdict(list)
    all_locations: dict[str, tuple[str, int]] = {}
    for fd in all_data:
        for cls_name, bases in fd.class_bases.items():
            for base in bases:
                children[base].append(cls_name)
        for cls_name in fd.class_names:
            all_locations[cls_name] = (fd.filepath, fd.class_lines.get(cls_name, 1))

    findings: list[Finding] = []
    for parent, subs in children.items():
        if len(subs) > MAX_DIRECT_SUBCLASSES and parent in all_locations:
            filepath, line = all_locations[parent]
            sub_names = subs[:5]
            findings.append(
                _make_finding(
                    file=filepath,
                    line=line,
                    pattern="SC309",
                    name="Wide Hierarchy",
                    severity="info",
                    message=f"Class `{parent}` has {len(subs)} direct subclasses: "
                    f"{', '.join(sub_names)}{'...' if len(subs) > 5 else ''} -- over-broad abstraction?",
                    category="types",
                )
            )
    return findings


def _detect_inappropriate_intimacy(all_data: list[FileData]) -> list[Finding]:
    """SC506 -- Classes that share too many attribute accesses."""
    intimacy: Counter[frozenset[str]] = Counter()
    class_files: dict[str, tuple[str, int]] = {}
    for fd in all_data:
        for ci in fd.class_info:
            class_files[ci.name] = (ci.filepath, ci.line)
            for other_cls, count in ci.external_class_accesses.items():
                if other_cls != ci.name:
                    key = frozenset({ci.name, other_cls})
                    intimacy[key] += count

    findings: list[Finding] = []
    for pair, count in intimacy.items():
        if count > INTIMACY_THRESHOLD:
            a, b = sorted(pair)
            if a in class_files:
                filepath, line = class_files[a]
                findings.append(
                    _make_finding(
                        file=filepath,
                        line=line,
                        pattern="SC506",
                        name="Inappropriate Intimacy",
                        severity="info",
                        message=f"Classes `{a}` and `{b}` share {count} attribute accesses -- decouple or merge",
                        category="architecture",
                    )
                )
    return findings


def _detect_speculative_generality(all_data: list[FileData]) -> list[Finding]:
    """SC507 -- Abstract classes with no concrete implementations."""
    all_bases_flat: dict[str, list[str]] = {}
    abstract_classes: set[str] = set()
    for fd in all_data:
        abstract_classes.update(fd.abstract_classes)
        for cls_name, bases in fd.class_bases.items():
            all_bases_flat[cls_name] = bases

    concrete_children: Counter[str] = Counter()
    for cls_name, bases in all_bases_flat.items():
        if cls_name not in abstract_classes:
            for base in bases:
                if base in abstract_classes:
                    concrete_children[base] += 1

    findings: list[Finding] = []
    for abc_cls in abstract_classes:
        if concrete_children[abc_cls] == 0:
            for fd in all_data:
                if abc_cls in fd.class_names:
                    findings.append(
                        _make_finding(
                            file=fd.filepath,
                            line=fd.class_lines.get(abc_cls, 1),
                            pattern="SC507",
                            name="Remove Speculative Generality",
                            severity="info",
                            message=f"Abstract class `{abc_cls}` has no concrete implementations -- YAGNI?",
                            category="architecture",
                        )
                    )
                    break
    return findings


def _detect_unstable_dependency(all_data: list[FileData]) -> list[Finding]:
    """SC508 -- Module depends on a more unstable module (Robert Martin's I metric)."""
    module_map = {fd.filepath: Path(fd.filepath).stem for fd in all_data}
    reverse_map: dict[str, str] = {v: k for k, v in module_map.items()}

    outgoing: dict[str, set[str]] = defaultdict(set)
    incoming: dict[str, set[str]] = defaultdict(set)
    for fd in all_data:
        src = module_map[fd.filepath]
        for imp in fd.imports:
            if imp in reverse_map:
                outgoing[src].add(imp)
                incoming[imp].add(src)

    instability: dict[str, float] = {}
    for module in module_map.values():
        ce = len(outgoing.get(module, set()))
        ca = len(incoming.get(module, set()))
        total = ca + ce
        instability[module] = ce / total if total > 0 else 0.0

    findings: list[Finding] = []
    for module in module_map.values():
        my_i = instability[module]
        for dep in outgoing.get(module, set()):
            dep_i = instability.get(dep, 0.0)
            if dep_i > my_i and dep_i > 0.7:
                filepath = reverse_map[module]
                findings.append(
                    _make_finding(
                        file=filepath,
                        line=1,
                        pattern="SC508",
                        name="Unstable Dependency",
                        severity="info",
                        message=f"Module `{module}` (I={my_i:.2f}) depends on unstable `{dep}` (I={dep_i:.2f})",
                        category="architecture",
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Cross-file analysis (second pass) -- Tier 3: OO metrics
# ---------------------------------------------------------------------------


def _detect_low_cohesion(all_data: list[FileData]) -> list[Finding]:
    """SC801 -- Lack of Cohesion of Methods."""
    findings: list[Finding] = []
    for fd in all_data:
        for ci in fd.class_info:
            if ci.method_count < 3 or ci.field_count < 2:
                continue
            methods_fields = ci.methods_using_fields
            all_fields = set(ci.all_fields)
            if not all_fields or not methods_fields:
                continue
            # Exclude __init__ from cohesion calc (it initializes all fields)
            method_set = {m: f for m, f in methods_fields.items() if m != "__init__"}
            if not method_set:
                continue
            total_usage = sum(
                len(fields & all_fields) for fields in method_set.values()
            )
            max_possible = len(method_set) * len(all_fields)
            if max_possible == 0:
                continue
            cohesion = total_usage / max_possible
            lcom = 1.0 - cohesion
            if lcom > MAX_LCOM:
                findings.append(
                    _make_finding(
                        file=ci.filepath,
                        line=ci.line,
                        pattern="SC801",
                        name="Low Class Cohesion",
                        severity="warning",
                        message=f"Class `{ci.name}` has LCOM={lcom:.2f} "
                        f"(threshold: {MAX_LCOM}) -- consider splitting",
                        category="metrics",
                    )
                )
    return findings


def _detect_high_coupling(all_data: list[FileData]) -> list[Finding]:
    """SC802 -- Coupling Between Objects."""
    findings: list[Finding] = []
    for fd in all_data:
        for ci in fd.class_info:
            coupled_classes = len(ci.external_class_accesses)
            if coupled_classes > MAX_CBO:
                findings.append(
                    _make_finding(
                        file=ci.filepath,
                        line=ci.line,
                        pattern="SC802",
                        name="High Coupling Between Objects",
                        severity="warning",
                        message=f"Class `{ci.name}` is coupled to {coupled_classes} other classes "
                        f"(threshold: {MAX_CBO})",
                        category="metrics",
                    )
                )
    return findings


def _detect_fan_out(all_data: list[FileData]) -> list[Finding]:
    """SC803 -- Excessive module fan-out (outgoing dependencies)."""
    module_map = {fd.filepath: Path(fd.filepath).stem for fd in all_data}
    reverse_map: dict[str, str] = {v: k for k, v in module_map.items()}

    findings: list[Finding] = []
    for fd in all_data:
        src = module_map[fd.filepath]
        outgoing = {imp for imp in fd.imports if imp in reverse_map}
        if len(outgoing) > MAX_FANOUT:
            findings.append(
                _make_finding(
                    file=fd.filepath,
                    line=1,
                    pattern="SC803",
                    name="Excessive Fan-Out",
                    severity="info",
                    message=f"Module `{src}` has {len(outgoing)} outgoing dependencies "
                    f"(threshold: {MAX_FANOUT}) -- too many dependencies",
                    category="metrics",
                )
            )
    return findings


def _detect_high_rfc(all_data: list[FileData]) -> list[Finding]:
    """SC804 -- Response for a Class (own methods + directly called external methods)."""
    findings: list[Finding] = []
    for fd in all_data:
        for ci in fd.class_info:
            own_methods = ci.method_count
            external_calls = len(ci.external_method_calls)
            rfc = own_methods + external_calls
            if rfc > MAX_RFC:
                findings.append(
                    _make_finding(
                        file=ci.filepath,
                        line=ci.line,
                        pattern="SC804",
                        name="High Response for Class",
                        severity="info",
                        message=f"Class `{ci.name}` has RFC={rfc} "
                        f"({own_methods} methods + {external_calls} external calls) "
                        f"(threshold: {MAX_RFC})",
                        category="metrics",
                    )
                )
    return findings


def _detect_middle_man(all_data: list[FileData]) -> list[Finding]:
    """SC805 -- Class where most methods just delegate to another object."""
    findings: list[Finding] = []
    for fd in all_data:
        for ci in fd.class_info:
            if ci.non_dunder_method_count < 3:
                continue
            ratio = ci.delegation_count / ci.non_dunder_method_count
            if ratio > MIDDLE_MAN_RATIO:
                findings.append(
                    _make_finding(
                        file=ci.filepath,
                        line=ci.line,
                        pattern="SC805",
                        name="Remove Middle Man",
                        severity="info",
                        message=f"Class `{ci.name}` delegates {ci.delegation_count}/{ci.non_dunder_method_count} "
                        f"methods ({ratio:.0%}) -- consider removing the middleman",
                        category="types",
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Cross-file analysis dispatcher
# ---------------------------------------------------------------------------


def cross_file_analysis(all_data: list[FileData]) -> list[Finding]:
    """Analyze patterns across files: all cross-file and metric checks."""
    findings: list[Finding] = []
    # Original patterns
    findings.extend(_detect_duplicate_functions(all_data))
    findings.extend(_detect_cyclic_imports(all_data))
    findings.extend(_detect_god_modules(all_data))
    findings.extend(_detect_feature_envy(all_data))
    # Tier 2: cross-file patterns
    findings.extend(_detect_shotgun_surgery(all_data))
    findings.extend(_detect_deep_inheritance(all_data))
    findings.extend(_detect_wide_hierarchy(all_data))
    findings.extend(_detect_inappropriate_intimacy(all_data))
    findings.extend(_detect_speculative_generality(all_data))
    findings.extend(_detect_unstable_dependency(all_data))
    # Tier 3: OO metrics
    findings.extend(_detect_low_cohesion(all_data))
    findings.extend(_detect_high_coupling(all_data))
    findings.extend(_detect_fan_out(all_data))
    findings.extend(_detect_high_rfc(all_data))
    findings.extend(_detect_middle_man(all_data))
    return findings


def scan_path(target: Path) -> list[Finding]:
    """Scan a file or directory recursively. Two-pass: per-file then cross-file."""
    all_findings: list[Finding] = []
    all_file_data: list[FileData] = []

    if target.is_file():
        if target.suffix == ".py":
            findings, fd = scan_file(target)
            all_findings.extend(findings)
            if fd:
                all_file_data.append(fd)
    elif target.is_dir():
        for py_file in sorted(target.rglob("*.py")):
            parts = py_file.parts
            if any(
                p
                in {
                    ".venv",
                    "venv",
                    "__pycache__",
                    ".tox",
                    ".eggs",
                    "node_modules",
                    ".git",
                }
                for p in parts
            ):
                continue
            findings, fd = scan_file(py_file)
            all_findings.extend(findings)
            if fd:
                all_file_data.append(fd)

    if len(all_file_data) > 1:
        all_findings.extend(cross_file_analysis(all_file_data))
    elif len(all_file_data) == 1:
        # Single-file scan: still compute per-class metrics (LCOM, CBO, RFC, MID)
        all_findings.extend(_detect_low_cohesion(all_file_data))
        all_findings.extend(_detect_high_coupling(all_file_data))
        all_findings.extend(_detect_high_rfc(all_file_data))
        all_findings.extend(_detect_middle_man(all_file_data))

    return all_findings


_SKIP_DIRS: Final = frozenset(
    {
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".eggs",
        "node_modules",
        ".git",
        ".smellcheck-cache",
    }
)


def _collect_py_files(target: Path) -> list[Path]:
    """Collect .py files from a single path (file or directory)."""
    if target.is_file():
        return [target] if target.suffix == ".py" else []
    if target.is_dir():
        return [
            p
            for p in sorted(target.rglob("*.py"))
            if not any(part in _SKIP_DIRS for part in p.parts)
        ]
    return []


def scan_paths(
    targets: list[Path],
    *,
    config: dict | None = None,
    cache_dir: Path | None = None,
    use_cache: bool = True,
) -> list[Finding]:
    """Scan multiple paths, aggregate findings, run cross-file analysis once.

    Parameters
    ----------
    targets:
        Files or directories to scan.
    config:
        Optional ``[tool.smellcheck]`` config dict. When provided, findings
        matching ``ignore`` patterns or ``per-file-ignores`` are removed, and
        only ``select`` patterns are kept (if specified).
    cache_dir:
        Directory for file-level cache.  Defaults to ``.smellcheck-cache``
        relative to the first target's parent.  Set *use_cache* to ``False``
        to disable.
    use_cache:
        When ``True`` (default), skip re-analysis of unchanged files.
    """
    all_findings: list[Finding] = []
    all_file_data: list[FileData] = []
    seen: set[Path] = set()

    # Resolve cache directory
    _cache: Path | None = None
    _cfghash: str = ""
    _version: str = ""
    if use_cache:
        if cache_dir is not None:
            _cache = cache_dir
        else:
            # Default: .smellcheck-cache next to first target
            anchor = targets[0] if targets else Path.cwd()
            if anchor.is_file():
                anchor = anchor.parent
            _cache = anchor / _DEFAULT_CACHE_DIR
        _cfghash = _config_hash(config)
        try:
            from smellcheck import __version__
            _version = __version__
        except Exception:
            _version = "unknown"

    for target in targets:
        for py_file in _collect_py_files(target):
            resolved = py_file.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)

            # Try cache before expensive scan
            if _cache is not None:
                try:
                    source = py_file.read_text(encoding="utf-8")
                except (UnicodeDecodeError, PermissionError):
                    continue
                key = _cache_key(source, _cfghash, _version)
                cached = _read_cache(_cache, key)
                if cached is not None:
                    findings, fd = cached
                    all_findings.extend(findings)
                    all_file_data.append(fd)
                    continue
                # Cache miss — scan (reuse already-read source) and write
                findings, fd = scan_file(py_file, source=source)
                all_findings.extend(findings)
                if fd:
                    all_file_data.append(fd)
                    _write_cache(_cache, key, findings, fd)
            else:
                findings, fd = scan_file(py_file)
                all_findings.extend(findings)
                if fd:
                    all_file_data.append(fd)

    if len(all_file_data) > 1:
        all_findings.extend(cross_file_analysis(all_file_data))
    elif len(all_file_data) == 1:
        all_findings.extend(_detect_low_cohesion(all_file_data))
        all_findings.extend(_detect_high_coupling(all_file_data))
        all_findings.extend(_detect_high_rfc(all_file_data))
        all_findings.extend(_detect_middle_man(all_file_data))

    # --- Apply inline + block suppression ---
    source_cache: dict[str, list[str]] = {}
    directive_cache: dict[
        str,
        tuple[dict[str, list[tuple[int, int]]], bool, frozenset[str]],
    ] = {}
    filtered: list[Finding] = []
    for f in all_findings:
        if f.file not in source_cache:
            try:
                source_cache[f.file] = (
                    Path(f.file).read_text(encoding="utf-8").splitlines()
                )
            except Exception:
                source_cache[f.file] = []
        if f.file not in directive_cache:
            bm, daf, fdc = _parse_block_directives(source_cache[f.file])
            directive_cache[f.file] = (bm, daf, frozenset(fdc))
        bm, daf, fdc = directive_cache[f.file]
        if not _is_suppressed(
            source_cache[f.file], f.line, f.pattern,
            block_map=bm, disable_all_file=daf, file_disabled_codes=fdc,
        ):
            filtered.append(f)
    all_findings = filtered

    # --- Apply config-based filtering ---
    if config:
        select = config.get("select")
        ignore = config.get("ignore", [])
        per_file_ignores = config.get("per-file-ignores", {})

        if select is not None:
            select_set: set[str] = set()
            for s in select:
                resolved = _resolve_code(s)
                select_set.update(
                    resolved if resolved else {f"#{s}" if not s.startswith("#") else s}
                )
            all_findings = [f for f in all_findings if f.pattern in select_set]

        if ignore:
            ignore_set: set[str] = set()
            for s in ignore:
                resolved = _resolve_code(s)
                ignore_set.update(
                    resolved if resolved else {f"#{s}" if not s.startswith("#") else s}
                )
            all_findings = [f for f in all_findings if f.pattern not in ignore_set]

        if per_file_ignores:
            import fnmatch

            result = []
            for f in all_findings:
                suppressed = False
                for glob_pat, codes in per_file_ignores.items():
                    code_set: set[str] = set()
                    for c in codes:
                        resolved = _resolve_code(c)
                        code_set.update(
                            resolved
                            if resolved
                            else {f"#{c}" if not c.startswith("#") else c}
                        )
                    if fnmatch.fnmatch(f.file, glob_pat) and f.pattern in code_set:
                        suppressed = True
                        break
                if not suppressed:
                    result.append(f)
            all_findings = result

    return all_findings


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

SEVERITY_COLORS: Final = {
    "error": "\033[91m",
    "warning": "\033[93m",
    "info": "\033[96m",
}
RESET: Final = "\033[0m"
BOLD: Final = "\033[1m"


def _print_summary(filtered: list[Finding]):
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in filtered:
        by_file[f.file].append(f)

    counts = Counter(f.severity for f in filtered)
    pattern_counts = Counter(f.pattern for f in filtered)

    print(f"\n{BOLD}{'=' * SEPARATOR_WIDTH}")
    print(f" Python Smell Detector -- {len(filtered)} findings")
    print(f"{'=' * SEPARATOR_WIDTH}{RESET}")
    print(
        f"  {SEVERITY_COLORS['error']}errors: {counts.get('error', 0)}{RESET}  "
        f"{SEVERITY_COLORS['warning']}warnings: {counts.get('warning', 0)}{RESET}  "
        f"{SEVERITY_COLORS['info']}info: {counts.get('info', 0)}{RESET}"
    )
    print()

    for filepath, file_findings in sorted(by_file.items()):
        print(f"{BOLD}{filepath}{RESET}")
        for f in sorted(file_findings, key=lambda x: x.line):
            color = SEVERITY_COLORS.get(f.severity, "")
            sev = f.severity.upper()[:4]
            print(f"  {color}{sev}{RESET} L{f.line:<5} {f.pattern} {f.name}")
            print(f"         {f.message}")
        print()

    print(f"{BOLD}Top patterns:{RESET}")
    for pattern, count in pattern_counts.most_common(10):
        matching = next((f for f in filtered if f.pattern == pattern), None)
        name = matching.name if matching else ""
        print(f"  {pattern} {name}: {count}")
    print()


def _print_github_annotations(filtered: list[Finding]):
    """Print findings as GitHub Actions workflow annotations."""
    _GH_SEV = {"error": "error", "warning": "warning", "info": "notice"}
    for f in filtered:
        sev = _GH_SEV.get(f.severity, "notice")
        title = f"{f.pattern} {f.name}"
        print(f"::{sev} file={f.file},line={f.line},title={title}::{f.message}")


_SARIF_LEVEL = {"error": "error", "warning": "warning", "info": "note"}

_SARIF_REF_BASE = (
    "https://github.com/cheickmec/smellcheck/blob/main/"
    "plugins/python-refactoring/skills/python-refactoring/references"
)


def _sarif_rule(rd: RuleDef) -> dict:
    """Build a SARIF reportingDescriptor (rule) from a RuleDef."""
    desc = _RULE_DESCRIPTIONS.get(rd.rule_id, rd.name)
    help_uri = f"{_SARIF_REF_BASE}/{rd.family}.md"
    help_md = (
        f"## {rd.name} ({rd.rule_id})\n\n"
        f"{desc}\n\n"
        f"**Family:** {rd.family} | "
        f"**Scope:** {rd.scope} | "
        f"**Default severity:** {rd.default_severity}\n\n"
        f"[View refactoring guide]({help_uri})"
    )
    return {
        "id": rd.rule_id,
        "name": rd.name,
        "shortDescription": {"text": rd.name},
        "fullDescription": {"text": desc},
        "helpUri": help_uri,
        "help": {"text": desc, "markdown": help_md},
        "defaultConfiguration": {
            "level": _SARIF_LEVEL.get(rd.default_severity, "note"),
        },
        "properties": {
            "family": rd.family,
            "scope": rd.scope,
        },
    }


def _sarif_result(f: Finding, rule_index: dict[str, int]) -> dict:
    """Build a SARIF result from a Finding."""
    try:
        rel = Path(f.file).resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        rel = Path(f.file).name
    fp_raw = f"{f.pattern}\0{rel}\0{_normalize_message(f.message)}"
    fp_hash = hashlib.sha256(fp_raw.encode()).hexdigest()
    result: dict = {
        "ruleId": f.pattern,
        "level": _SARIF_LEVEL.get(f.severity, "note"),
        "message": {"text": f.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": rel},
                    "region": {"startLine": f.line},
                }
            }
        ],
        "partialFingerprints": {"primaryLocationLineHash": fp_hash},
    }
    if f.pattern in rule_index:
        result["ruleIndex"] = rule_index[f.pattern]
    return result


def _format_sarif(filtered: list[Finding]) -> str:
    """Format findings as SARIF 2.1.0 JSON for GitHub Code Scanning upload."""
    from smellcheck import __version__

    # Collect unique rules that appear in findings
    seen_rules: dict[str, RuleDef] = {}
    for f in filtered:
        if f.pattern not in seen_rules:
            rd = _RULE_REGISTRY.get(f.pattern)
            if rd:
                seen_rules[f.pattern] = rd

    rules = []
    rule_index: dict[str, int] = {}
    for idx, (rule_id, rd) in enumerate(seen_rules.items()):
        rule_index[rule_id] = idx
        rules.append(_sarif_rule(rd))

    results = [_sarif_result(f, rule_index) for f in filtered]

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "smellcheck",
                        "version": __version__,
                        "informationUri": "https://github.com/cheickmec/smellcheck",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def print_findings(
    findings: list[Finding],
    use_json: bool = False,
    min_severity: str = "info",
    *,
    output_format: str | None = None,
):
    """Print findings in the requested format.

    Parameters
    ----------
    output_format:
        ``"text"`` (default), ``"json"``, ``"github"``, or ``"sarif"``.
        When *None*, falls back to ``use_json`` for backward compatibility.
    """
    fmt = output_format or ("json" if use_json else "text")
    min_rank = SEVERITY_ORDER.get(min_severity, 0)
    filtered = [f for f in findings if f.severity_rank >= min_rank]

    if fmt == "json":
        print(json.dumps([asdict(f) for f in filtered], indent=2))
    elif fmt == "github":
        _print_github_annotations(filtered)
    elif fmt == "sarif":
        print(_format_sarif(filtered))
    elif not filtered:
        print(f"{BOLD}No code smells found.{RESET}")
    else:
        _print_summary(filtered)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _explain(code: str) -> None:
    """Print documentation for a rule, a family prefix, or all rules."""
    code = code.strip()

    # --- Single rule: SC701 ---
    if code.upper() in _RULE_REGISTRY:
        code = code.upper()
        rule = _RULE_REGISTRY[code]
        desc = _RULE_DESCRIPTIONS.get(code, "")
        example = _RULE_EXAMPLES.get(code)
        family_prefix = code[:3] + "xx"
        family_label = _FAMILY_LABELS.get(rule.family, rule.family)

        print(f"{code}: {rule.name}")
        print(f"Family:   {family_label} ({family_prefix})")
        print(f"Severity: {rule.default_severity}")
        print(f"Scope:    {rule.scope}")
        if desc:
            print()
            print(textwrap.indent(desc, "  "))
        if example is not None:
            before, after = example
            print()
            print("  Before:")
            print(textwrap.indent(before, "    "))
            print()
            print("  After:")
            print(textwrap.indent(after, "    "))
        print()
        print(f"Suppress:")
        print(f"  Line:  # noqa: {code}")
        print(f"  Block: # smellcheck: disable {code}  ...  # smellcheck: enable {code}")
        print(f"  File:  # smellcheck: disable-file {code}")
        return

    # --- Family prefix: SC4 or SC4xx → all SC4xx rules ---
    upper = code.upper()
    prefix = None
    if len(upper) == 3 and upper.startswith("SC") and upper[2].isdigit():
        prefix = upper
    elif len(upper) == 5 and upper.startswith("SC") and upper[2].isdigit() and upper[3:] == "XX":
        prefix = upper[:3]
    if prefix is not None:
        matched = {c: r for c, r in _RULE_REGISTRY.items() if c.startswith(prefix)}
        if not matched:
            print(f"No rules found with prefix {prefix}xx", file=sys.stderr)
            sys.exit(1)
        first = next(iter(matched.values()))
        family_label = _FAMILY_LABELS.get(first.family, first.family)
        print(f"{prefix}xx \u2014 {family_label}")
        for c, r in matched.items():
            print(f"  {c}  {r.name:<45s} {r.default_severity}")
        return

    # --- All rules ---
    if upper == "ALL" or code == "":
        families: dict[str, list[tuple[str, RuleDef]]] = {}
        for c, r in _RULE_REGISTRY.items():
            families.setdefault(r.family, []).append((c, r))
        for family_key in ["state", "functions", "types", "control", "architecture", "hygiene", "idioms", "metrics"]:
            rules = families.get(family_key, [])
            if not rules:
                continue
            prefix = rules[0][0][:3] + "xx"
            label = _FAMILY_LABELS.get(family_key, family_key)
            print(f"{prefix} \u2014 {label}")
            for c, r in rules:
                print(f"  {c}  {r.name:<45s} {r.default_severity}")
            print()
        return

    # --- Unknown ---
    print(f"Unknown rule or prefix: {code}", file=sys.stderr)
    print("Use --explain SC701, --explain SC4, or --explain all", file=sys.stderr)
    sys.exit(1)


_HELP_TEXT: Final = textwrap.dedent("""\
    Usage: smellcheck <path> [path ...] [options]
           smellcheck --explain [CODE]

    Scan Python files for code smells mapped to the 83-pattern refactoring catalog.

    Detects 56 patterns programmatically:
      - 41 per-file (AST analysis)    — SC1xx..SC7xx (scope: file)
      - 10 cross-file (import graph)  — SC3xx..SC6xx (scope: cross_file)
      - 5 OO metrics (LCOM, CBO, …)   — SC8xx        (scope: metric)

    Options:
      --format FMT        Output format: text | json | github | sarif (default: text)
      --json              Deprecated alias for --format json
      --fail-on SEV       Exit 1 if any finding >= SEV: info | warning | error
                          (default: error)
      --min-severity SEV  Only display findings >= SEV: info | warning | error
                          (default: info)
      --select CODES      Only run these checks (comma-separated, e.g. SC701,SC601)
      --ignore CODES      Skip these checks (comma-separated, e.g. SC601,SC202)
      --scope SCOPE       Only show findings of this scope: file | cross_file | metric
      --explain [CODE]     Show rule docs: SC701, SC4 (family), or all
      --no-cache          Disable file-level caching
      --cache-dir PATH    Custom cache directory (default: .smellcheck-cache)
      --clear-cache       Delete cached results and exit
      --generate-baseline Output a JSON baseline of current findings to stdout
      --baseline PATH     Compare against baseline; only report new findings
      --version           Show version and exit
      -h, --help          Show this help

    Rule codes:
      Each rule has an SC code (e.g. SC701). SC codes are used in --select,
      --ignore, and # noqa comments.

    Suppression:
      Line:   ``# noqa: SC701`` suppresses SC701 on that line.
      Block:  ``# smellcheck: disable SC701`` … ``# smellcheck: enable SC701``
      File:   ``# smellcheck: disable-file SC701`` at top of file.
      All:    ``# smellcheck: disable-all`` … ``# smellcheck: enable-all``

    Configuration:
      smellcheck reads [tool.smellcheck] from the nearest pyproject.toml.
      CLI flags override config values.

    Baseline workflow:
      smellcheck src/ --generate-baseline > .smellcheck-baseline.json
      smellcheck src/ --baseline .smellcheck-baseline.json --fail-on warning
      Also configurable: baseline = ".smellcheck-baseline.json" in [tool.smellcheck]

    Examples:
      smellcheck src/
      smellcheck myfile.py --format json
      smellcheck src/ --min-severity warning --fail-on warning
      smellcheck src/ --scope file
      smellcheck file1.py file2.py --format github
""")


def _pop_option(args: list[str], flag: str) -> str | None:
    """Remove *flag* and its value from *args*, returning the value or None."""
    if flag not in args:
        return None
    idx = args.index(flag)
    if idx + 1 >= len(args):
        print(f"Error: {flag} requires a value", file=sys.stderr)
        sys.exit(1)
    value = args[idx + 1]
    del args[idx : idx + 2]
    return value


def _parse_args(
    argv: list[str],
) -> tuple[list[Path], str, str, str, list[str] | None, list[str] | None, str | None]:
    """Parse CLI arguments.

    Returns ``(paths, output_format, min_severity, fail_on, select, ignore, scope_filter)``.
    """
    args = list(argv)

    if "--version" in args:
        from smellcheck import __version__

        print(f"smellcheck {__version__}")
        sys.exit(0)

    if not args or "--help" in args or "-h" in args:
        print(_HELP_TEXT)
        sys.exit(0)

    # --format
    output_format = _pop_option(args, "--format") or "text"
    # --json (deprecated alias)
    if "--json" in args:
        args.remove("--json")
        output_format = "json"

    if output_format not in {"text", "json", "github", "sarif"}:
        print(
            f"Error: invalid format '{output_format}' -- must be one of: text, json, github, sarif",
            file=sys.stderr,
        )
        sys.exit(1)

    # --fail-on
    fail_on = _pop_option(args, "--fail-on") or "error"
    if fail_on not in SEVERITY_ORDER:
        print(
            f"Error: invalid --fail-on '{fail_on}' -- must be one of: info, warning, error",
            file=sys.stderr,
        )
        sys.exit(1)

    # --min-severity
    min_severity = _pop_option(args, "--min-severity") or "info"
    if min_severity not in SEVERITY_ORDER:
        print(
            f"Error: invalid --min-severity '{min_severity}' -- must be one of: info, warning, error",
            file=sys.stderr,
        )
        sys.exit(1)

    # --select / --ignore
    select_raw = _pop_option(args, "--select")
    ignore_raw = _pop_option(args, "--ignore")
    select = [c.strip() for c in select_raw.split(",")] if select_raw else None
    ignore = [c.strip() for c in ignore_raw.split(",")] if ignore_raw else None

    # --scope
    scope_filter = _pop_option(args, "--scope")
    if scope_filter is not None and scope_filter not in _VALID_SCOPES:
        print(
            f"Error: invalid --scope '{scope_filter}' -- must be one of: file, cross_file, metric",
            file=sys.stderr,
        )
        sys.exit(1)

    # Remaining args are paths
    if not args:
        print("Error: at least one path is required", file=sys.stderr)
        sys.exit(1)

    paths: list[Path] = []
    for a in args:
        p = Path(a).resolve()
        if not p.exists():
            print(f"Error: {p} does not exist", file=sys.stderr)
            sys.exit(1)
        paths.append(p)

    return paths, output_format, min_severity, fail_on, select, ignore, scope_filter


def main():
    raw_args = list(sys.argv[1:])

    # --explain: show rule documentation and exit (no paths needed)
    if "--explain" in raw_args:
        idx = raw_args.index("--explain")
        if idx + 1 < len(raw_args) and not raw_args[idx + 1].startswith("-"):
            code = raw_args[idx + 1]
            del raw_args[idx : idx + 2]
            _explain(code)
        else:
            raw_args.remove("--explain")
            _explain("all")
        sys.exit(0)

    # Extract cache flags before _parse_args (avoids path validation)
    no_cache = "--no-cache" in raw_args
    if no_cache:
        raw_args.remove("--no-cache")
    cache_dir_str = _pop_option(raw_args, "--cache-dir")
    clear_cache = "--clear-cache" in raw_args
    if clear_cache:
        raw_args.remove("--clear-cache")

    if clear_cache:
        cdir = Path(cache_dir_str) if cache_dir_str else Path(_DEFAULT_CACHE_DIR)
        removed = _clear_cache(cdir)
        print(f"Cleared {removed} cached entries from {cdir}")
        sys.exit(0)

    # Extract baseline flags before _parse_args (avoids path validation)
    generate_baseline = "--generate-baseline" in raw_args
    if generate_baseline:
        raw_args.remove("--generate-baseline")
    baseline_path_str = _pop_option(raw_args, "--baseline")

    if generate_baseline and baseline_path_str:
        print(
            "Error: --generate-baseline and --baseline are mutually exclusive",
            file=sys.stderr,
        )
        sys.exit(1)

    paths, output_format, min_severity, fail_on, select, ignore, scope_filter = (
        _parse_args(
            raw_args,
        )
    )

    # Load config from nearest pyproject.toml
    config = load_config(paths[0])

    # CLI --select / --ignore override config
    if select is not None:
        config["select"] = select
    if ignore is not None:
        config["ignore"] = ignore

    # Config fallback for --baseline
    if baseline_path_str is None and not generate_baseline:
        baseline_path_str = config.get("baseline")

    # Resolve cache config (CLI overrides pyproject.toml)
    use_cache = not no_cache
    if use_cache and config.get("cache") is False:
        use_cache = False
    resolved_cache_dir: Path | None = None
    if cache_dir_str:
        resolved_cache_dir = Path(cache_dir_str)
    elif config.get("cache-dir"):
        resolved_cache_dir = Path(config["cache-dir"])

    findings = scan_paths(
        paths,
        config=config,
        cache_dir=resolved_cache_dir,
        use_cache=use_cache,
    )

    # Apply --scope filter
    if scope_filter is not None:
        findings = [f for f in findings if f.scope == scope_filter]

    # Generate baseline mode
    if generate_baseline:
        print(_generate_baseline_json(findings, Path.cwd()))
        sys.exit(0)

    # Compare against baseline
    if baseline_path_str:
        baseline_fps = _load_baseline(Path(baseline_path_str))
        findings, suppressed = _filter_baseline(findings, baseline_fps, Path.cwd())
        print(
            f"{len(findings)} new findings (baseline: {suppressed} suppressed)",
            file=sys.stderr,
        )

    print_findings(findings, min_severity=min_severity, output_format=output_format)

    fail_rank = SEVERITY_ORDER.get(fail_on, 2)
    has_fail = any(f.severity_rank >= fail_rank for f in findings)
    sys.exit(1 if has_fail else 0)


if __name__ == "__main__":
    main()
