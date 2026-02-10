# Code Hygiene Patterns

## 003 — Extract Constant

**Smell:** Magic numbers and strings with no explanation.

```python
# Before
def calculate_shipping(weight):
    if weight > 50: return weight * 2.5
    return weight * 1.2

# After
MAX_STANDARD_WEIGHT_KG = 50
HEAVY_RATE_PER_KG = 2.5
STANDARD_RATE_PER_KG = 1.2

def calculate_shipping(weight):
    if weight > MAX_STANDARD_WEIGHT_KG: return weight * HEAVY_RATE_PER_KG
    return weight * STANDARD_RATE_PER_KG
```

## 004 — Remove Unhandled Exceptions

**Smell:** Empty exception classes or bare catch blocks nobody uses.

```python
# Before
class CacheException(Exception): pass  # never raised or caught

try:
    result = fetch_data()
except Exception:
    pass  # swallowed silently

# After
class DatabaseError(Exception):
    """Raised when a database query fails."""

try:
    result = fetch_data()
except DatabaseError as e:
    logger.error(f"DB fetch failed: {e}")
    raise
```

## 011 — Replace Comments with Tests

**Smell:** Comments rot. Tests don't (they fail loudly).

```python
# Before
def leap_year(year):
    # divisible by 4, but not 100, unless also 400
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)

# After — the comment becomes tests
def test_common_leap_year():
    assert leap_year(2024) is True

def test_century_not_leap():
    assert leap_year(1900) is False

def test_400_year_is_leap():
    assert leap_year(2000) is True
```

## 013 — Remove Repeated Code

**Smell:** Same logic copy-pasted in multiple places.

```python
# Before — email validation in create_admin AND create_customer
def create_admin(name, email):
    if not email or "@" not in email: raise ValueError("Invalid email")
    return Admin(name=name, email=email)

def create_customer(name, email):
    if not email or "@" not in email: raise ValueError("Invalid email")
    return Customer(name=name, email=email)

# After
def validate_email(email: str):
    if not email or "@" not in email: raise ValueError("Invalid email")

def create_admin(name, email):
    validate_email(email)
    return Admin(name=name, email=email)

def create_customer(name, email):
    validate_email(email)
    return Customer(name=name, email=email)
```

## 021 — Remove Dead Code

**Smell:** Unused functions, unreachable branches, commented-out blocks.

```python
# Before
# def calculate_tax_v2(amount):
#     return amount * 0.085  # TODO: maybe use this later?

def old_shipping_logic(weight):  # nothing calls this
    return weight * 3.5

# After — delete it. Git remembers.
```

## 025 — Decompose Regular Expressions

**Smell:** One giant unreadable regex for complex validation.

```python
# Before
def validate_url(url: str) -> bool:
    return bool(re.match(
        r"^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[\w./-]*)?(\?[\w=&]*)?(#\w*)?$", url
    ))

# After — named parts
PROTOCOL = re.compile(r"^https?://")
DOMAIN = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
PATH = re.compile(r"^(/[\w./-]*)?$")

def validate_url(url: str) -> str:
    if not PROTOCOL.match(url): raise ValueError("Must start with http(s)://")
    rest = re.sub(r"^https?://", "", url)
    domain = rest.split("/")[0].split("?")[0].split("#")[0]
    if not DOMAIN.match(domain): raise ValueError(f"Invalid domain: {domain}")
    return url
```

## 031 — Removing OOPs (Cryptic Errors)

**Smell:** Error messages that don't help the user.

```python
# Before
raise Exception("Error 500")
raise ValueError("Invalid input")

# After
raise PaymentDeclinedError(
    "Your card was declined. Please check the card number and try again."
)
raise InvalidAgeError(
    f"Age must be between 0 and 150, but got {age}."
)
```

## 032 — Apply Consistent Style Rules

**Smell:** Inconsistent formatting across files and contributors.

```toml
# pyproject.toml
[tool.ruff]
select = ["E", "F", "I", "UP"]
line-length = 88
```

```bash
ruff check . --fix && ruff format .
```

No more style debates. The formatter decides.

## 033 — Strip Annotations

**Smell:** More decorators than logic.

```python
# Before
@staticmethod
@deprecated("use new_method instead")
@log_entry_and_exit
@validate_params
@cache_result
@retry(max_attempts=3)
def calculate(x, y): return x + y

# After — keep only what changes behavior meaningfully
@retry(max_attempts=3)
def calculate(x, y): return x + y
```

## 036 — Replace String Concatenation with Text Blocks

**Smell:** Messy `+` chains for multiline strings.

```python
# Before
html = "<html>\n" + "  <body>\n" + "    <h1>" + title + "</h1>\n" + "  </body>\n" + "</html>"

# After
html = f"""<html>
  <body>
    <h1>{title}</h1>
    <p>{body}</p>
  </body>
</html>"""
```
