"""Common finding schema, statuses, severity, and evidence redaction."""
from __future__ import annotations
import re, time, uuid
from dataclasses import dataclass, field, asdict
from typing import Optional

# Explicit finding statuses (spec section 10). A finding is never "confirmed"
# merely because text says so - confirmation requires observed evidence.
STATUS_CONFIRMED = "confirmed"
STATUS_POTENTIAL = "potential"
STATUS_NOT_DETECTED = "not-detected"
STATUS_NOT_TESTED = "not-tested"
STATUS_INCONCLUSIVE = "inconclusive"
STATUSES = {STATUS_CONFIRMED, STATUS_POTENTIAL, STATUS_NOT_DETECTED,
            STATUS_NOT_TESTED, STATUS_INCONCLUSIVE}

SEVERITIES = ("critical", "high", "medium", "low", "info")

SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9\-._~+/]+=*"),
    re.compile(r"(?i)(authorization:\s*basic\s+)[A-Za-z0-9+/]+=*"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)[A-Za-z0-9\-_]{8,}"),
    re.compile(r"(?i)(password\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(set-cookie:\s*[^=]+=)[^;\s]+"),
    re.compile(r"(?i)(token\s*[:=]\s*)[A-Za-z0-9\-._]{8,}"),
]

def redact(text: str) -> str:
    """Redact secrets, credentials, cookies and tokens before storage/display."""
    if not text:
        return text
    out = text
    for pat in SECRET_PATTERNS:
        out = pat.sub(lambda m: m.group(1) + "[REDACTED]", out)
    return out

@dataclass
class Finding:
    check_id: str
    title: str
    category: str
    severity: str            # one of SEVERITIES
    status: str              # one of STATUSES
    confidence: str          # high | medium | low
    asset: str               # affected URL / host
    description: str = ""
    evidence: str = ""       # sanitized, redacted
    impact: str = ""
    remediation: str = ""
    references: list = field(default_factory=list)
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    preconditions: str = ""
    kind: str = "vulnerability"   # vulnerability | hardening | observation
    id: str = field(default_factory=lambda: "fnd-" + uuid.uuid4().hex[:12])
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def __post_init__(self):
        assert self.status in STATUSES, f"bad status {self.status}"
        assert self.kind in ("vulnerability", "hardening", "observation")
        assert self.severity in SEVERITIES, f"bad severity {self.severity}"
        self.evidence = redact(self.evidence)
        self.description = redact(self.description)

    def to_dict(self):
        return asdict(self)
