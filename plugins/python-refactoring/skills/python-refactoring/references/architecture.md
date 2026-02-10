# Architecture & Dependency Patterns

## 018 — Replace Singleton

**Smell:** Global shared state disguised as a pattern.

```python
# Before
class Database:
    _instance = None
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

# After — inject the dependency
class Database:
    def __init__(self, connection_string: str):
        self.conn = connect(connection_string)

class UserRepository:
    def __init__(self, db: Database):
        self.db = db

# Production: db = Database("postgres://...")
# Tests: db = Database("sqlite:///:memory:")
```

## 024 — Replace Global Variables with DI

**Smell:** Hidden state through module-level globals.

```python
# Before
config = load_config("/etc/app.yaml")  # module-level global

def get_api_url():
    return config["api_url"]  # hidden dependency

# After
@dataclass(frozen=True)
class AppConfig:
    api_url: str
    db_host: str

class ApiClient:
    def __init__(self, config: AppConfig):
        self.base_url = config.api_url

client = ApiClient(AppConfig(api_url="https://api.prod.com", db_host="db.prod"))
```

## 028 — Replace Consecutive IDs with Dark Keys

**Smell:** Sequential IDs leak information and enable scraping.

```python
# Before
class User:
    _counter = 0
    def __init__(self, name):
        User._counter += 1
        self.id = User._counter  # /users/1, /users/2 ... guessable

# After
import uuid

class User:
    def __init__(self, name):
        self.id = str(uuid.uuid4())  # opaque, non-sequential
        self.name = name
```

## 035 — Separate Exception Types

**Smell:** Same exception for business rules and infrastructure failures.

```python
# Before
raise Exception("Insufficient funds")
raise Exception("Database connection timeout")

# After
class BusinessRuleViolation(Exception):
    """User did something invalid — show them the message."""

class InsufficientFundsError(BusinessRuleViolation): pass

class InfrastructureError(Exception):
    """System failure — retry or alert ops."""

class DatabaseTimeoutError(InfrastructureError): pass

# Caller can handle differently:
try:
    transfer(from_acct, to_acct, amount)
except BusinessRuleViolation as e:
    show_user(str(e))
except InfrastructureError:
    retry_or_alert()
```

## 045 — Introduce Assertion

**Smell:** Code assumes things not made explicit — failures happen far from cause.

```python
# Before
def apply_discount(price, rate):
    return price * (1 - rate)
# rate=1.5 → negative price, discovered 3 layers later

# After — fail fast
def apply_discount(price: float, rate: float) -> float:
    if not (0 <= rate < 1):
        raise ValueError(f"Discount rate must be in [0, 1), got {rate}")
    if price < 0:
        raise ValueError(f"Price must be non-negative, got {price}")
    return price * (1 - rate)
```

## 051 — Replace Error Code with Exception

**Smell:** Return codes that callers forget to check.

```python
# Before
def withdraw(account, amount) -> int:
    if amount > account.balance: return -1  # error code
    account.balance -= amount
    return 0

# After — exceptions are impossible to ignore
class InsufficientFundsError(Exception):
    def __init__(self, balance, amount):
        super().__init__(f"Cannot withdraw ${amount:.2f} from ${balance:.2f}")

def withdraw(account, amount):
    if amount > account.balance:
        raise InsufficientFundsError(account.balance, amount)
    account.balance -= amount
```

## 054 — Hide Delegate (Law of Demeter)

**Smell:** Chained attribute access couples you to the entire object graph.

```python
# Before
manager_name = employee.department.manager.name
# If Department restructures → everything breaks

# After — ask the nearest object
class Employee:
    def __init__(self, name, department):
        self.name = name
        self._department = department

    @property
    def manager_name(self) -> str:
        return self._department.manager_name

class Department:
    def __init__(self, manager):
        self._manager = manager

    @property
    def manager_name(self) -> str:
        return self._manager.name

manager_name = employee.manager_name  # only talks to employee
```
