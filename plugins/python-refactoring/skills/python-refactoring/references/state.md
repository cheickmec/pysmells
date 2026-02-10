# State & Immutability Patterns

## 001 — Remove Setters

**Smell:** Mutable state via setters leads to half-built objects.

```python
# Before
class User:
    def __init__(self):
        self.name = None
        self.email = None
    def set_name(self, name): self.name = name
    def set_email(self, email): self.email = email

# After
from dataclasses import dataclass

@dataclass(frozen=True)
class User:
    name: str
    email: str
```

## 008 — Convert Variables to Constants

**Smell:** Values that never change declared as mutable variables.

```python
# Before
def connect():
    host = "db.example.com"
    port = 5432
    timeout = 30
    return create_connection(host, port, timeout)

# After
DB_HOST = "db.example.com"
DB_PORT = 5432
CONNECTION_TIMEOUT_SECONDS = 30

def connect():
    return create_connection(DB_HOST, DB_PORT, CONNECTION_TIMEOUT_SECONDS)
```

## 009 — Protect Public Attributes

**Smell:** Exposed internals let anyone mutate state arbitrarily.

```python
# Before
class BankAccount:
    def __init__(self, balance):
        self.balance = balance  # anyone can set to -9999

# After
class BankAccount:
    def __init__(self, initial_balance: float):
        if initial_balance < 0:
            raise ValueError("Balance cannot be negative")
        self._balance = initial_balance

    def deposit(self, amount: float):
        if amount <= 0:
            raise ValueError("Deposit must be positive")
        self._balance += amount

    def withdraw(self, amount: float):
        if amount > self._balance:
            raise ValueError("Insufficient funds")
        self._balance -= amount
```

## 016 — Build With The Essence

**Smell:** Objects created empty, then populated piecemeal.

```python
# Before
class CreditCard:
    def __init__(self):
        self.number = None
        self.holder = None
        self.expiry = None
        self.cvv = None

# After
@dataclass(frozen=True)
class CreditCard:
    number: str
    holder: str
    expiry: str
    cvv: str

    def __post_init__(self):
        if len(self.cvv) != 3:
            raise ValueError("CVV must be 3 digits")
```

## 017 — Convert Attributes to Sets

**Smell:** Boolean flags for every possible state/role.

```python
# Before
class User:
    def __init__(self):
        self.is_admin = False
        self.is_premium = False
        self.is_verified = False
        self.is_banned = False

# After
class User:
    def __init__(self, name: str, roles: frozenset[str] = frozenset()):
        self.name = name
        self.roles = roles

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def with_role(self, role: str) -> "User":
        return User(self.name, self.roles | {role})
```

## 030 — Inline Attributes

**Smell:** Redundant cached/derived attributes that can go stale.

```python
# Before
class Cart:
    def __init__(self):
        self.items = []
        self.total = 0  # must manually keep in sync

    def add(self, item):
        self.items.append(item)
        self.total += item.price  # forget this once → wrong

# After
class Cart:
    def __init__(self):
        self.items = []

    def add(self, item):
        self.items.append(item)

    @property
    def total(self):
        return sum(item.price for item in self.items)  # always correct
```
