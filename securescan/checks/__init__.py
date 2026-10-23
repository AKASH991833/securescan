"""Check registry. A check is a callable(ctx) -> list[Finding].
ctx carries the safe client, the guard, and cached baseline responses."""
from . import builtin
REGISTRY = {c.id: c for c in builtin.CHECKS}
