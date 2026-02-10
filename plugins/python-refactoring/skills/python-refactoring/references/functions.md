# Function & Method Design Patterns

## 002 — Extract Method

**Smell:** Long functions doing multiple things.

```python
# Before
def process_order(order):
    if not order.items:
        raise ValueError("Empty order")
    if order.total < 0:
        raise ValueError("Negative total")
    if order.total > 100:
        order.total *= 0.9
    send_email(order.customer.email, f"Order {order.id} confirmed")

# After
def process_order(order):
    validate(order)
    apply_discount(order)
    send_confirmation(order)

def validate(order):
    if not order.items: raise ValueError("Empty order")
    if order.total < 0: raise ValueError("Negative total")

def apply_discount(order):
    if order.total > 100: order.total *= 0.9

def send_confirmation(order):
    send_email(order.customer.email, f"Order {order.id} confirmed")
```

## 005 — Replace Comment with Function Name

**Smell:** Comments explaining what code does instead of naming it.

```python
# Before
def process(data):
    # Remove entries older than 30 days
    filtered = [d for d in data if (now() - d.created_at).days <= 30]
    # Calculate the average score
    avg = sum(d.score for d in filtered) / len(filtered)
    return avg

# After
def average_recent_score(data, days=30):
    recent = entries_within(data, days)
    return average_score(recent)

def entries_within(data, days):
    return [d for d in data if (now() - d.created_at).days <= days]

def average_score(entries):
    return sum(e.score for e in entries) / len(entries)
```

## 006 — Rename Result Variables

**Smell:** Generic names like `result`, `res`, `data`, `tmp`.

```python
# Before
def get_data(users):
    result = []
    for u in users:
        if u.is_active: result.append(u)
    return result

# After
def active_users(users):
    return [user for user in users if user.is_active]
```

## 010 — Extract Method Object

**Smell:** Massive method with tons of local variables and branching.

```python
# Before
def generate_report(transactions, start, end, tax_rate, discount):
    filtered = [t for t in transactions if start <= t.date <= end]
    subtotal = sum(t.amount for t in filtered)
    tax = subtotal * tax_rate
    discounted = (subtotal + tax) * (1 - discount)
    return {"total": discounted, "items": len(filtered)}

# After
class ReportGenerator:
    def __init__(self, transactions, start, end, tax_rate, discount):
        self.transactions = transactions
        self.start = start
        self.end = end
        self.tax_rate = tax_rate
        self.discount = discount

    def generate(self):
        filtered = self._filter_by_date()
        subtotal = self._subtotal(filtered)
        total = self._apply_tax_and_discount(subtotal)
        return {"total": total, "items": len(filtered)}

    def _filter_by_date(self):
        return [t for t in self.transactions if self.start <= t.date <= self.end]

    def _subtotal(self, txns):
        return sum(t.amount for t in txns)

    def _apply_tax_and_discount(self, subtotal):
        return (subtotal * (1 + self.tax_rate)) * (1 - self.discount)
```

## 020 — Transform Static Functions

**Smell:** Static/module-level functions that hide dependencies.

```python
# Before
import requests

def fetch_price(ticker: str) -> float:
    resp = requests.get(f"https://api.stocks.com/{ticker}")
    return resp.json()["price"]

# After — injectable dependency
class PriceFetcher:
    def __init__(self, client):
        self.client = client

    def fetch(self, ticker: str) -> float:
        resp = self.client.get(f"https://api.stocks.com/{ticker}")
        return resp.json()["price"]

# Testable with a fake client
```

## 026 — Migrate Console Input to Declarative Function

**Smell:** `input()` baked into business logic.

```python
# Before
def get_user_age():
    age = int(input("Enter your age: "))  # untestable
    if age < 0: raise ValueError("Invalid age")
    return age

# After
def get_user_age(age: int) -> int:
    if age < 0: raise ValueError("Invalid age")
    return age

# CLI layer calls input(), business logic is pure
```

## 027 — Remove Getters

**Smell:** Getters expose data, encouraging "ask then do" patterns.

```python
# Before
class Order:
    def __init__(self, items):
        self._items = items
    def get_items(self): return self._items

total = sum(item.price for item in order.get_items())

# After — tell, don't ask
class Order:
    def __init__(self, items):
        self._items = items

    def total(self) -> float:
        return sum(item.price for item in self._items)
```

## 034 — Reify Parameters

**Smell:** Long parameter lists of related values.

```python
# Before
def create_shipment(street, city, state, zip_code, country, weight, carrier): ...

# After
@dataclass(frozen=True)
class Address:
    street: str
    city: str
    state: str
    zip_code: str
    country: str

@dataclass(frozen=True)
class ShipmentRequest:
    destination: Address
    weight_kg: float
    carrier: str

def create_shipment(request: ShipmentRequest): ...
```

## 037 — Testing Private Methods

**Smell:** Wanting to test a private method → hidden concept begging to escape.

```python
# Before — tempted to test _validate_items directly
class OrderProcessor:
    def process(self, order):
        validated = self._validate_items(order.items)
        return self._calculate_total(validated)
    def _validate_items(self, items): ...  # 30 lines
    def _calculate_total(self, items): ...  # 20 lines

# After — extract the hidden concepts
class ItemValidator:
    def validate(self, items) -> list: ...

class PricingCalculator:
    def total(self, items) -> float: ...

class OrderProcessor:
    def __init__(self, validator: ItemValidator, pricing: PricingCalculator):
        self.validator = validator
        self.pricing = pricing

    def process(self, order):
        validated = self.validator.validate(order.items)
        return self.pricing.total(validated)
```

## 041 — Separate Query from Modifier (CQS)

**Smell:** Function both returns a value and changes state.

```python
# Before — calling twice applies discount twice
class ShoppingCart:
    def get_total_and_apply_discount(self):
        self.total = sum(i.price for i in self.items)
        if self.total > 100: self.total *= 0.9
        return self.total

# After — query and command separated
class ShoppingCart:
    @property
    def total(self) -> float:
        """Query — no side effects."""
        return sum(i.price for i in self.items)

    def apply_discount(self):
        """Command — changes state, returns nothing."""
        if self.total > 100: self._discount = 0.1

    @property
    def discounted_total(self) -> float:
        return self.total * (1 - getattr(self, "_discount", 0))
```

## 050 — Parameterize Function

**Smell:** Near-duplicate functions differing by one value.

```python
# Before
def raise_salary_by_5_percent(employee): employee.salary *= 1.05
def raise_salary_by_10_percent(employee): employee.salary *= 1.10
def raise_salary_by_15_percent(employee): employee.salary *= 1.15

# After
def raise_salary(employee, percent: float):
    employee.salary *= 1 + percent / 100
```

## 052 — Preserve Whole Object

**Smell:** Extracting fields from an object just to pass them individually.

```python
# Before
send_notification(user.name, user.email, user.phone, user.preference)

# After — pass the whole object
def send_notification(user):
    message = f"Hello {user.name}"
    if user.preference == "email":
        send_email(user.email, message)
    else:
        send_sms(user.phone, message)
```
