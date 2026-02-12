<!-- template:feature -->

## What does this PR do?

Brief description of the change.

## Type of change

- [ ] New smell check
- [ ] CLI / output improvement
- [ ] Other feature

## Checklist

- [ ] `pytest tests/ -v` passes
- [ ] New check has a test in `tests/test_detector.py`
- [ ] `smellcheck src/smellcheck/` self-check runs clean (or new findings are intentional)
- [ ] No dependencies added (stdlib only)
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)

## For new smell checks

- **Pattern number**: `#___`
- **SC code**: `SC___`
- **Severity**: error / warning / info
- **Family**: state / functions / types / control / architecture / hygiene / idioms / metrics

**Before** (smelly code):

```python
# paste example
```

**After** (clean code):

```python
# paste example
```

## Test plan

How was this tested?

## Additional context

Any other context, edge cases, or related issues.
