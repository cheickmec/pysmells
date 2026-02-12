# OO Metrics -- Refactoring Patterns

Object-oriented metrics that identify structural problems in class design. These are quantitative measures that flag classes needing refactoring attention.

---

## LCOM -- Lack of Cohesion of Methods

**Smell**: A class has methods that operate on disjoint sets of instance attributes, indicating the class has multiple unrelated responsibilities.

**Metric**: LCOM = 1 - (sum of method-field usage / (methods * fields)). Values close to 1.0 indicate low cohesion.

**Threshold**: LCOM > 0.8

### Before
```python
class UserManager:
    def __init__(self, db, mailer, logger):
        self.db = db
        self.mailer = mailer
        self.logger = logger
        self.cache = {}

    def get_user(self, user_id):
        # Uses: self.db, self.cache
        if user_id in self.cache:
            return self.cache[user_id]
        user = self.db.query(user_id)
        self.cache[user_id] = user
        return user

    def send_welcome(self, email):
        # Uses: self.mailer only
        self.mailer.send("Welcome!", email)

    def send_reminder(self, email):
        # Uses: self.mailer only
        self.mailer.send("Reminder!", email)

    def log_action(self, action):
        # Uses: self.logger only
        self.logger.info(action)

    def log_error(self, error):
        # Uses: self.logger only
        self.logger.error(error)
```

LCOM is high: `get_user` touches {db, cache}, `send_*` touches {mailer}, `log_*` touches {logger}. Three disjoint groups.

### After
```python
class UserRepository:
    def __init__(self, db):
        self.db = db
        self.cache = {}

    def get_user(self, user_id):
        if user_id in self.cache:
            return self.cache[user_id]
        user = self.db.query(user_id)
        self.cache[user_id] = user
        return user


class NotificationService:
    def __init__(self, mailer):
        self.mailer = mailer

    def send_welcome(self, email):
        self.mailer.send("Welcome!", email)

    def send_reminder(self, email):
        self.mailer.send("Reminder!", email)


class ActionLogger:
    def __init__(self, logger):
        self.logger = logger

    def log_action(self, action):
        self.logger.info(action)

    def log_error(self, error):
        self.logger.error(error)
```

Each class now has high cohesion -- all methods use all (or most) fields.

**Trade-offs**: More classes to manage, but each is focused and independently testable. Constructor injection makes dependencies explicit.

---

## CBO -- Coupling Between Objects

**Smell**: A class depends on too many other classes, making it fragile to changes elsewhere.

**Metric**: Count of distinct external classes referenced (via attribute access, method calls, type annotations, imports used in class body).

**Threshold**: CBO > 8

### Before
```python
class OrderProcessor:
    def __init__(self):
        self.db = Database()
        self.cache = RedisCache()
        self.validator = OrderValidator()
        self.pricer = PricingEngine()
        self.tax = TaxCalculator()
        self.inventory = InventoryService()
        self.payment = PaymentGateway()
        self.shipping = ShippingService()
        self.notifier = EmailNotifier()
        self.logger = AuditLogger()

    def process(self, order):
        self.validator.validate(order)
        price = self.pricer.calculate(order)
        tax = self.tax.compute(order, price)
        self.inventory.reserve(order.items)
        self.payment.charge(order.customer, price + tax)
        self.shipping.schedule(order)
        self.notifier.send_confirmation(order)
        self.logger.log(order)
        self.db.save(order)
        self.cache.invalidate(order.customer_id)
```

CBO = 10. Any change to any of those 10 classes may break OrderProcessor.

### After
```python
class OrderProcessor:
    """Orchestrates order processing through a pipeline."""

    def __init__(self, pipeline: list[OrderStep]):
        self.pipeline = pipeline

    def process(self, order: Order) -> OrderResult:
        context = OrderContext(order)
        for step in self.pipeline:
            step.execute(context)
        return context.result


class OrderStep(Protocol):
    def execute(self, context: OrderContext) -> None: ...


class ValidateOrder:
    def __init__(self, validator: OrderValidator):
        self.validator = validator

    def execute(self, context: OrderContext) -> None:
        self.validator.validate(context.order)


class ChargePayment:
    def __init__(self, payment: PaymentGateway, tax: TaxCalculator):
        self.payment = payment
        self.tax = tax

    def execute(self, context: OrderContext) -> None:
        tax = self.tax.compute(context.order, context.price)
        self.payment.charge(context.order.customer, context.price + tax)
```

CBO of OrderProcessor drops to 3 (OrderStep protocol, Order, OrderResult). Each step has CBO of 1-2.

**Trade-offs**: More indirection via pipeline pattern, but each class is independently testable and changes are localized.

---

## FIO -- Excessive Fan-Out

**Smell**: A class or module calls methods on too many distinct external classes, indicating it knows too much about the system.

**Metric**: Count of distinct external classes whose methods are called from within the class.

**Threshold**: Fan-out > 15

### Before
```python
class ReportGenerator:
    def generate(self, report_id):
        config = ConfigLoader.load()
        data = DatabaseClient.query(report_id)
        user = UserService.get_current()
        perms = PermissionChecker.check(user, "reports")
        template = TemplateEngine.load("report.html")
        formatter = DataFormatter.create("table")
        chart = ChartRenderer.render(data)
        header = HeaderBuilder.build(user, config)
        footer = FooterBuilder.build(config)
        css = StyleManager.get_styles("report")
        pdf = PdfConverter.convert(template, data)
        cache = CacheManager.get_instance()
        cache.store(report_id, pdf)
        Metrics.record("report_generated")
        AuditLog.write("report", report_id, user)
        EmailService.notify(user, "Report ready")
        return pdf
```

Fan-out = 16. This function is a "god method" that orchestrates everything.

### After
```python
class ReportGenerator:
    def __init__(self, data_source: ReportDataSource, renderer: ReportRenderer):
        self.data_source = data_source
        self.renderer = renderer

    def generate(self, report_id: str) -> Report:
        data = self.data_source.fetch(report_id)
        return self.renderer.render(data)


class ReportDataSource:
    def __init__(self, db: DatabaseClient, cache: CacheManager):
        self.db = db
        self.cache = cache

    def fetch(self, report_id: str) -> ReportData:
        cached = self.cache.get(report_id)
        if cached:
            return cached
        data = self.db.query(report_id)
        self.cache.store(report_id, data)
        return data


class ReportRenderer:
    def __init__(self, template: TemplateEngine, formatter: DataFormatter):
        self.template = template
        self.formatter = formatter

    def render(self, data: ReportData) -> Report:
        formatted = self.formatter.format(data)
        return self.template.render("report.html", formatted)
```

Fan-out per class: 2-3. Each class handles one aspect of report generation.

**Trade-offs**: More classes, but each has a clear single responsibility and minimal knowledge of the broader system.

---

## RFC -- Response for a Class

**Smell**: A class has too large a "response set" -- the total number of methods that can be called in response to a message to the class.

**Metric**: RFC = number of methods defined in class + number of distinct external methods called by those methods.

**Threshold**: RFC > 20

### Before
```python
class ShoppingCart:
    def __init__(self, db, pricer, tax_calc, coupon_svc, inventory, logger):
        self.db = db
        self.pricer = pricer
        self.tax_calc = tax_calc
        self.coupon_svc = coupon_svc
        self.inventory = inventory
        self.logger = logger
        self.items = []

    def add_item(self, product_id, qty):
        product = self.db.get_product(product_id)
        available = self.inventory.check_stock(product_id)
        if available < qty:
            self.logger.warn(f"Low stock: {product_id}")
            raise OutOfStockError(product_id)
        price = self.pricer.get_price(product_id)
        self.items.append(CartItem(product, qty, price))
        self.logger.info(f"Added {product_id}")

    def apply_coupon(self, code):
        discount = self.coupon_svc.validate(code)
        self.coupon_svc.reserve(code)
        self.logger.info(f"Coupon {code} applied")
        return discount

    def get_total(self):
        subtotal = self.pricer.calculate_subtotal(self.items)
        tax = self.tax_calc.compute(self.items)
        shipping = self.pricer.calculate_shipping(self.items)
        self.logger.info(f"Total: {subtotal + tax + shipping}")
        return subtotal + tax + shipping

    def checkout(self):
        total = self.get_total()
        self.inventory.reserve_all(self.items)
        order = self.db.create_order(self.items, total)
        self.logger.info(f"Order {order.id} created")
        return order
```

RFC = 4 own methods + 13 external calls = 17, approaching threshold. With a few more methods this class becomes hard to reason about.

### After
```python
class ShoppingCart:
    """Pure domain object -- no external dependencies."""

    def __init__(self):
        self.items: list[CartItem] = []

    def add_item(self, item: CartItem):
        self.items.append(item)

    def remove_item(self, product_id: str):
        self.items = [i for i in self.items if i.product_id != product_id]

    @property
    def subtotal(self) -> Decimal:
        return sum(item.line_total for item in self.items)


class CartService:
    """Thin orchestration layer with focused dependencies."""

    def __init__(self, inventory: InventoryService, pricer: PricingEngine):
        self.inventory = inventory
        self.pricer = pricer

    def add_to_cart(self, cart: ShoppingCart, product_id: str, qty: int):
        self.inventory.check_stock(product_id)
        price = self.pricer.get_price(product_id)
        cart.add_item(CartItem(product_id, qty, price))
```

ShoppingCart RFC = 3 (own methods only, no external calls). CartService RFC = 4. Each is well within threshold.

**Trade-offs**: Separating domain model from service layer adds a class, but the cart becomes pure (easy to test, serialize, reason about).

---

## MID -- Middle Man

**Smell**: A class does almost nothing except delegate to another object. It adds a layer of indirection with no value.

**Metric**: If >50% of a class's non-dunder methods consist solely of delegating to another object, the class is a middle man.

**Threshold**: Delegation ratio > 0.5

### Before
```python
class UserService:
    def __init__(self, repo: UserRepository):
        self.repo = repo

    def get_user(self, user_id):
        return self.repo.get_user(user_id)

    def save_user(self, user):
        return self.repo.save_user(user)

    def delete_user(self, user_id):
        return self.repo.delete_user(user_id)

    def list_users(self):
        return self.repo.list_users()

    def count_users(self):
        return self.repo.count_users()
```

5/5 methods (100%) are pure delegation. This class adds no value.

### After

**Option A**: Remove the middle man. Let callers use `UserRepository` directly.

```python
# Before: service.get_user(user_id)
# After:  user_repo.get_user(user_id)
```

**Option B**: If the class exists for a reason (e.g., future business logic), add the actual logic:

```python
class UserService:
    def __init__(self, repo: UserRepository, event_bus: EventBus):
        self.repo = repo
        self.event_bus = event_bus

    def get_user(self, user_id: str) -> User:
        return self.repo.get_user(user_id)

    def create_user(self, data: UserInput) -> User:
        user = User.from_input(data)
        self.repo.save_user(user)
        self.event_bus.publish(UserCreated(user.id))
        return user

    def deactivate_user(self, user_id: str) -> None:
        user = self.repo.get_user(user_id)
        user.deactivate()
        self.repo.save_user(user)
        self.event_bus.publish(UserDeactivated(user_id))
```

Now the service layer adds real value: event publishing, domain operations, orchestration.

**Trade-offs**: Removing middle men reduces indirection but may lose a convenient extension point. Prefer removal unless there's a concrete (not speculative) reason for the layer.

---

## Cross-References

| Metric | Related Patterns | Connection |
|--------|-----------------|------------|
| SC801 | SC201 (extract method), SC301 (extract class) | Low cohesion often means the class should be split |
| SC802 | SC502 (Law of Demeter), #020 (dependency injection) | High coupling indicates tight dependencies |
| SC803 | SC201 (extract method), #047 (separate phases) | High fan-out means the method does too much |
| SC804 | SC206 (too many params), #052 (parameter objects) | High RFC correlates with complex interfaces |
| SC805 | SC306 (lazy class) | Middle men are a special case of lazy classes that only delegate |

## Detection

All five metrics are detected by `detect_smells.py`:

```bash
python detect_smells.py src/              # includes OO metrics in output
python detect_smells.py src/ --json       # structured JSON with metric values
python detect_smells.py src/ --min-severity warning  # filter noise
```

The detector computes metrics from cross-file analysis, collecting class information across the entire codebase before calculating scores.
