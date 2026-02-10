# Control Flow & Algorithm Patterns

## 039 — Replace Nested Conditional with Guard Clauses

**Smell:** Deep nesting makes the "happy path" hard to find.

```python
# Before
def calculate_pay(employee):
    if employee.is_active:
        if employee.is_salaried:
            if employee.tenure > 5:
                return employee.base * 1.2
            else:
                return employee.base
        else:
            return employee.hours * employee.rate
    else:
        return 0

# After — early returns flatten the logic
def calculate_pay(employee):
    if not employee.is_active:
        return 0
    if not employee.is_salaried:
        return employee.hours * employee.rate
    if employee.tenure > 5:
        return employee.base * 1.2
    return employee.base
```

## 040 — Replace Loop with Pipeline

**Smell:** Imperative loops with accumulation logic.

```python
# Before
def active_premium_emails(users):
    result = []
    for user in users:
        if user.is_active:
            if user.plan == "premium":
                result.append(user.email.lower())
    return sorted(result)

# After — declarative pipeline
def active_premium_emails(users):
    return sorted(
        user.email.lower()
        for user in users
        if user.is_active and user.plan == "premium"
    )
```

For complex pipelines, use intermediate names:

```python
def process_orders(orders):
    pending = (o for o in orders if o.status == "pending")
    valued = (o for o in pending if o.total > 0)
    sorted_orders = sorted(valued, key=lambda o: o.created_at)
    return [summarize(o) for o in sorted_orders]
```

## 042 — Decompose Conditional

**Smell:** Complex boolean expressions hard to parse mentally.

```python
# Before
if (booking.date.month >= 6 and booking.date.month <= 8
        and booking.guests > 4 and not booking.is_corporate):
    return booking.base_rate * 1.5

# After — name the conditions
def calculate_rate(booking):
    if is_peak_season_group(booking):
        return peak_rate(booking)
    return standard_rate(booking)

def is_peak_season_group(booking) -> bool:
    return is_summer(booking.date) and booking.guests > 4 and not booking.is_corporate

def is_summer(date) -> bool:
    return 6 <= date.month <= 8
```

## 043 — Extract Variable (Introduce Explaining Variable)

**Smell:** Long expressions hard to read and debug.

```python
# Before
def price(order):
    return (order.quantity * order.item_price
        - max(0, order.quantity - 500) * order.item_price * 0.05
        + min(order.quantity * order.item_price * 0.1, 100))

# After — name the parts
def price(order):
    base_price = order.quantity * order.item_price
    quantity_discount = max(0, order.quantity - 500) * order.item_price * 0.05
    shipping = min(base_price * 0.1, 100)
    return base_price - quantity_discount + shipping
```

## 046 — Split Loop

**Smell:** One loop doing two unrelated things.

```python
# Before
def summarize(employees):
    total_salary = 0
    youngest = employees[0]
    for emp in employees:
        total_salary += emp.salary
        if emp.age < youngest.age: youngest = emp
    return total_salary, youngest

# After — each has one job
def total_salary(employees) -> float:
    return sum(emp.salary for emp in employees)

def youngest_employee(employees):
    return min(employees, key=lambda e: e.age)
```

## 047 — Split Phase

**Smell:** One function mixes parsing, computing, and formatting.

```python
# Before — parse, compute, format all in one
def generate_invoice(raw_json: str) -> str:
    data = json.loads(raw_json)
    total = 0
    lines = []
    for item in data["items"]:
        line_total = item["qty"] * item["price"]
        total += line_total
        lines.append(f"  {item['name']}: ${line_total:.2f}")
    tax = total * 0.08
    lines.append(f"  Tax: ${tax:.2f}")
    return "\n".join(lines)

# After — separate phases
@dataclass
class InvoiceLine:
    name: str
    quantity: int
    unit_price: float
    @property
    def total(self) -> float: return self.quantity * self.unit_price

@dataclass
class Invoice:
    customer: str
    lines: list[InvoiceLine]
    tax_rate: float = 0.08
    @property
    def subtotal(self): return sum(l.total for l in self.lines)
    @property
    def tax(self): return self.subtotal * self.tax_rate
    @property
    def total(self): return self.subtotal + self.tax

def parse_invoice(raw: str) -> Invoice:
    data = json.loads(raw)
    lines = [InvoiceLine(i["name"], i["qty"], i["price"]) for i in data["items"]]
    return Invoice(customer=data["customer"], lines=lines)

def format_invoice(inv: Invoice) -> str:
    lines = [f"  {l.name}: ${l.total:.2f}" for l in inv.lines]
    lines.append(f"  Tax: ${inv.tax:.2f}")
    lines.append(f"  Total: ${inv.total:.2f}")
    return f"Invoice for {inv.customer}\n" + "\n".join(lines)
```

## 049 — Substitute Algorithm

**Smell:** Clunky algorithm when a simpler one exists.

```python
# Before
def find_person(people, names_to_find):
    found = []
    for person in people:
        for name in names_to_find:
            if person.name == name:
                if person not in found: found.append(person)
    return found

# After
def find_person(people, names_to_find):
    target_names = set(names_to_find)
    return [p for p in people if p.name in target_names]
```

## 053 — Slide Statements

**Smell:** Related lines scattered, hard to see what belongs together.

```python
# Before
def process_order(order):
    discount = calculate_discount(order)
    log.info(f"Processing order {order.id}")
    shipping = calculate_shipping(order)
    total = order.subtotal - discount + shipping
    notify_warehouse(order)
    charge_customer(order.customer, total)

# After — group related operations
def process_order(order):
    log.info(f"Processing order {order.id}")

    discount = calculate_discount(order)
    shipping = calculate_shipping(order)
    total = order.subtotal - discount + shipping

    charge_customer(order.customer, total)
    notify_warehouse(order)
```

## 055 — Replace Control Flag with Break

**Smell:** Boolean flags controlling loop flow.

```python
# Before
def has_criminal_record(people):
    found = False
    for person in people:
        if not found:
            if person.has_record: found = True
    return found

# After
def has_criminal_record(people):
    return any(person.has_record for person in people)
```

## 056 — Pattern Matching for Dispatch (Python 3.10+)

**Smell:** Complex if/elif dispatch chains.

```python
# Before
def handle_command(command):
    if command["type"] == "create":
        if "name" in command: return create_item(command["name"])
        else: raise ValueError("Missing name")
    elif command["type"] == "delete":
        if "id" in command: return delete_item(command["id"])
        else: raise ValueError("Missing id")

# After — structural pattern matching
def handle_command(command):
    match command:
        case {"type": "create", "name": name}: return create_item(name)
        case {"type": "delete", "id": item_id}: return delete_item(item_id)
        case {"type": "list"}: return list_items()
        case {"type": unknown}: raise ValueError(f"Unknown: {unknown}")
        case _: raise ValueError(f"Malformed: {command}")
```
