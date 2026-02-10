# Class & Type Design Patterns

## 007 — Extract Class

**Smell:** Related behavior scattered with no home.

```python
# Before — price logic in loose functions
def format_price(amount, currency):
    symbols = {"USD": "$", "EUR": "€", "GBP": "£"}
    return f"{symbols[currency]}{amount:.2f}"

def convert_price(amount, from_curr, to_curr, rates):
    return amount * rates[f"{from_curr}_{to_curr}"]

# After
@dataclass(frozen=True)
class Money:
    amount: float
    currency: str
    SYMBOLS = {"USD": "$", "EUR": "€", "GBP": "£"}

    def format(self) -> str:
        return f"{self.SYMBOLS[self.currency]}{self.amount:.2f}"

    def convert_to(self, target: str, rates: dict) -> "Money":
        rate = rates[f"{self.currency}_{target}"]
        return Money(self.amount * rate, target)
```

## 012 — Reify Associative Arrays

**Smell:** Dicts used as objects — no structure, typo-prone keys.

```python
# Before
user = {"name": "Cheick", "emial": "c@x.com", "age": 30}
print(user["email"])  # KeyError — typo undetected

# After
@dataclass
class User:
    name: str
    email: str
    age: int
# User(name="Cheick", emial="c@x.com", age=30) → TypeError immediately
```

## 014 — Replace IF with Polymorphism

**Smell:** Type-checking if/elif chains.

```python
# Before
def calculate_area(shape):
    if shape["type"] == "circle":
        return 3.14159 * shape["radius"] ** 2
    elif shape["type"] == "rectangle":
        return shape["width"] * shape["height"]

# After
from abc import ABC, abstractmethod
import math

class Shape(ABC):
    @abstractmethod
    def area(self) -> float: ...

@dataclass
class Circle(Shape):
    radius: float
    def area(self): return math.pi * self.radius ** 2

@dataclass
class Rectangle(Shape):
    width: float
    height: float
    def area(self): return self.width * self.height
```

## 015 — Remove NULL

**Smell:** `None` checks everywhere, crashes when you miss one.

```python
# Before
def find_user(user_id):
    user = db.get(user_id)
    if user is None: return None

# After — Null Object pattern
class NullUser:
    name = "Unknown"
    email = ""
    def notify(self): pass  # safe no-op

def find_user(user_id) -> User:
    return db.get(user_id) or NullUser()

# Or raise explicitly if absence is exceptional:
def find_user_strict(user_id) -> User:
    user = db.get(user_id)
    if user is None: raise UserNotFoundError(user_id)
    return user
```

## 019 — Reify Email Addresses

**Smell:** Email validation scattered everywhere as raw strings.

```python
# Before — regex duplicated in create_user, send_invite, etc.
def create_user(email: str):
    if not re.match(r"^[\w.+-]+@[\w-]+\.[\w.]+$", email):
        raise ValueError("Bad email")

# After
class EmailAddress:
    PATTERN = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.]+$")

    def __init__(self, value: str):
        if not self.PATTERN.match(value):
            raise ValueError(f"Invalid email: {value}")
        self._value = value

    def __str__(self): return self._value

# Validated once, trusted everywhere
def create_user(email: EmailAddress): ...
```

## 022 — Extract Common Ancestor

**Smell:** Duplicate behavior across sibling classes.

```python
# Before — Dog and Cat both have identical describe()
class Dog:
    def __init__(self, name): self.name = name
    def speak(self): return "Woof"
    def describe(self): return f"{self.name} says {self.speak()}"

class Cat:
    def __init__(self, name): self.name = name
    def speak(self): return "Meow"
    def describe(self): return f"{self.name} says {self.speak()}"

# After
class Animal(ABC):
    def __init__(self, name: str): self.name = name
    @abstractmethod
    def speak(self) -> str: ...
    def describe(self) -> str: return f"{self.name} says {self.speak()}"

class Dog(Animal):
    def speak(self): return "Woof"

class Cat(Animal):
    def speak(self): return "Meow"
```

## 023 — Replace Inheritance with Delegation

**Smell:** Inheriting for code reuse when "is-a" doesn't hold.

```python
# Before
class Robot(Brain):  # a robot IS-A brain? No.
    def act(self):
        decision = self.think()  # inherited

# After
class Robot:
    def __init__(self, brain: Brain):
        self.brain = brain  # a robot HAS-A brain

    def act(self):
        decision = self.brain.think()
        execute(decision)
```

## 029 — Replace NULL with Collection

**Smell:** Methods returning `None` or a list, forcing callers to check.

```python
# Before
def find_orders(customer_id) -> list | None:
    orders = db.query(customer_id)
    if not orders: return None

# After — always return a collection
def find_orders(customer_id) -> list:
    return db.query(customer_id) or []

# Caller — always safe, no check needed:
for o in find_orders(42): process(o)
```

## 038 — Reify Collection

**Smell:** Raw lists with no type safety or domain meaning.

```python
# Before
def notify_users(users: list):
    for user in users: user.send_notification()

users = [User("Cheick"), Product("Laptop")]  # Product snuck in

# After
class UserDirectory:
    def __init__(self, users: list[User]):
        if not all(isinstance(u, User) for u in users):
            raise TypeError("All elements must be User instances")
        self._users = list(users)

    def notify_all(self):
        for user in self._users: user.send_notification()

    def active(self) -> "UserDirectory":
        return UserDirectory([u for u in self._users if u.is_active])

    def __len__(self): return len(self._users)
    def __iter__(self): return iter(self._users)
```

## 044 — Replace Primitive with Object

**Smell:** Raw primitive carries implicit rules scattered everywhere.

```python
# Before — price/currency validation repeated in 10 places
def create_product(name: str, price: float, currency: str):
    if price < 0: raise ValueError(...)
    if currency not in ("USD", "EUR", "GBP"): raise ValueError(...)

# After
@dataclass(frozen=True)
class Money:
    amount: float
    currency: str
    SUPPORTED = {"USD", "EUR", "GBP"}

    def __post_init__(self):
        if self.amount < 0: raise ValueError(f"Negative: {self.amount}")
        if self.currency not in self.SUPPORTED: raise ValueError(f"Unsupported: {self.currency}")

    def __add__(self, other: "Money") -> "Money":
        if self.currency != other.currency: raise ValueError("Currency mismatch")
        return Money(self.amount + other.amount, self.currency)

def create_product(name: str, price: Money): ...  # no validation needed
```

## 048 — Replace Constructor with Factory Function

**Smell:** Constructor can't have a descriptive name or return different types.

```python
# Before — callers must know permission details for each role
admin = User("Cheick", "c@x.com", "admin", ["read", "write", "delete", "manage"])
viewer = User("Awa", "a@x.com", "viewer", ["read"])

# After — factory methods with clear intent
class User:
    def __init__(self, name, email, role, permissions):
        self.name, self.email = name, email
        self.role, self.permissions = role, permissions

    @classmethod
    def admin(cls, name: str, email: str) -> "User":
        return cls(name, email, "admin", ["read", "write", "delete", "manage"])

    @classmethod
    def viewer(cls, name: str, email: str) -> "User":
        return cls(name, email, "viewer", ["read"])

admin = User.admin("Cheick", "c@x.com")
```
