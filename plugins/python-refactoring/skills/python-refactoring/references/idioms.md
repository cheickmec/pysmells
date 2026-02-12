# Python-Specific Idioms

## 057 — Replace Mutable Default Arguments

**Smell:** The classic Python gotcha — mutable defaults shared across calls.

```python
# Before
def add_item(item, items=[]):
    items.append(item)
    return items

add_item("a")  # ["a"]
add_item("b")  # ["a", "b"] — same list object!

# After — use None sentinel
def add_item(item, items=None):
    if items is None:
        items = []
    items.append(item)
    return items
```

## 058 — Use Context Managers

**Smell:** Manual resource cleanup with try/finally.

```python
# Before
f = open(path)
try:
    data = json.load(f)
finally:
    f.close()

# After
with open(path) as f:
    data = json.load(f)

# For your own resources:
from contextlib import contextmanager

@contextmanager
def temporary_directory():
    path = create_temp_dir()
    try:
        yield path
    finally:
        shutil.rmtree(path)

with temporary_directory() as tmp:
    process_files(tmp)
```

## 059 — Use Generators for Lazy Evaluation

**Smell:** Building entire lists in memory when streaming suffices.

```python
# Before — 10GB file → 20GB+ in memory
def read_large_file(path):
    with open(path) as f:
        lines = f.readlines()  # entire file in memory
    results = []
    for line in lines:
        parsed = parse_line(line)
        if parsed.is_valid: results.append(parsed)
    return results

# After — O(1) memory regardless of file size
def read_large_file(path):
    with open(path) as f:
        for line in f:
            parsed = parse_line(line)
            if parsed.is_valid:
                yield parsed

# Compose lazily
valid = read_large_file("huge.csv")
high_value = (r for r in valid if r.amount > 1000)
first_10 = itertools.islice(high_value, 10)
```

## 060 — Replace Type Checking with Protocols

**Smell:** `isinstance()` dispatch scatters type logic and breaks open/closed.

```python
# Before — adding a new type requires editing serialize()
def serialize(obj):
    if isinstance(obj, User): return {"name": obj.name, "email": obj.email}
    elif isinstance(obj, Product): return {"title": obj.title, "price": obj.price}
    else: raise TypeError(f"Cannot serialize {type(obj)}")

# After — Protocol (structural subtyping)
from typing import Protocol, runtime_checkable

@runtime_checkable
class Serializable(Protocol):
    def to_dict(self) -> dict: ...

@dataclass
class User:
    name: str
    email: str
    def to_dict(self): return {"name": self.name, "email": self.email}

@dataclass
class Product:
    title: str
    price: float
    def to_dict(self): return {"title": self.title, "price": self.price}

def serialize(obj: Serializable) -> dict:
    return obj.to_dict()
# Adding new types requires zero changes to serialize()
```

## 061 — Replace Class with Dataclass / NamedTuple

**Smell:** Boilerplate `__init__`, `__repr__`, `__eq__` for data holders.

```python
# Before — 15 lines of boilerplate
class Point:
    def __init__(self, x, y):
        self.x = x; self.y = y
    def __repr__(self): return f"Point(x={self.x}, y={self.y})"
    def __eq__(self, other):
        return isinstance(other, Point) and self.x == other.x and self.y == other.y
    def __hash__(self): return hash((self.x, self.y))

# After — dataclass (mutable, with behavior)
from dataclasses import dataclass

@dataclass
class Point:
    x: float
    y: float
    def distance_to(self, other: "Point") -> float:
        return ((self.x - other.x) ** 2 + (self.y - other.y) ** 2) ** 0.5

# Or NamedTuple for immutable lightweight data:
from typing import NamedTuple

class Point(NamedTuple):
    x: float
    y: float
# Supports unpacking: x, y = point
```

## 062 — Use Unpacking Instead of Indexing

**Smell:** Accessing tuple/list elements by index is cryptic and fragile.

```python
# Before
name = record[0]
age = record[1]
scores = record[2:]

# After
name, age, *scores = record

# Also: swaps, nested, ignoring
first, *_, last = items
(x, y), (a, b) = pair_of_pairs
_, _, important = triple
```

## 071 — Avoid Blocking Calls in Async Functions

**Smell:** Calling synchronous I/O or CPU-bound functions inside `async def` blocks the event loop.

```python
# Before — blocks the entire event loop
import time
import requests

async def handle_request(url):
    time.sleep(1)                     # blocks!
    response = requests.get(url)      # blocks!
    data = open("config.json").read() # blocks!
    return response.text

# After — use async equivalents or offload to a thread
import asyncio
import aiohttp

async def handle_request(url):
    await asyncio.sleep(1)
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            data = await response.text()
    # For unavoidable sync calls, offload:
    config = await asyncio.to_thread(Path("config.json").read_text)
    return data
```

Common blocking calls and their async alternatives:

| Blocking | Alternative |
|----------|------------|
| `time.sleep()` | `await asyncio.sleep()` |
| `requests.get()` | `aiohttp` / `httpx.AsyncClient` |
| `open().read()` | `aiofiles.open()` or `asyncio.to_thread()` |
| `subprocess.run()` | `await asyncio.create_subprocess_exec()` |
| `os.path.exists()` | `await asyncio.to_thread(os.path.exists, ...)` |
| `input()` | framework-specific async input |

## 063 — Replace Manual Cleanup with contextlib

**Smell:** Full class for simple context managers.

```python
# Before — 8 lines for a timer
class Timer:
    def __enter__(self):
        self.start = time.perf_counter()
        return self
    def __exit__(self, *args):
        self.elapsed = time.perf_counter() - self.start

# After
from contextlib import contextmanager

@contextmanager
def timer(label=""):
    start = time.perf_counter()
    yield
    print(f"{label} {time.perf_counter() - start:.3f}s")

# Suppress exceptions:
from contextlib import suppress
with suppress(FileNotFoundError):
    os.remove("temp.txt")

# Combine multiple:
from contextlib import ExitStack
with ExitStack() as stack:
    files = [stack.enter_context(open(f)) for f in filenames]
    process_all(files)
```
