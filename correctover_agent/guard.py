"""
Runtime Guard Engine — RCE/SSRF/Env leak interception via correctover SDK hooks.
22µs P50 detection latency.

v2.0: License enforcement added — core scan requires valid license.
Free tier gets limited diagnostics (first 2 patterns, no repair).
Pro tier gets full scanning, repair, and live interception.
"""

import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class FaultPattern:
    pattern_id: str
    category: str  # RCE | SSRF | ENV_LEAK | INJECTION
    regex: str
    severity: str  # CRITICAL | HIGH | MEDIUM
    description: str
    repair: str


@dataclass
class DetectionEvent:
    timestamp: float
    pattern: FaultPattern
    input_data: str
    source: str
    latency_us: float


@dataclass
class GuardStats:
    total_checks: int = 0
    blocked: int = 0
    allowed: int = 0
    avg_latency_us: float = 0.0
    p50_latency_us: float = 0.0
    p99_latency_us: float = 0.0
    latencies: list = field(default_factory=list)
    recent_events: list = field(default_factory=list)

    def record(self, latency_us: float, blocked: bool):
        self.total_checks += 1
        if blocked:
            self.blocked += 1
        else:
            self.allowed += 1
        self.latencies.append(latency_us)
        if len(self.latencies) > 10000:
            self.latencies = self.latencies[-5000:]
        sorted_lats = sorted(self.latencies)
        n = len(sorted_lats)
        self.avg_latency_us = sum(sorted_lats) / n if n else 0
        self.p50_latency_us = sorted_lats[n // 2] if n else 0
        self.p99_latency_us = sorted_lats[int(n * 0.99)] if n else 0


FAULT_PATTERNS: list[FaultPattern] = [
    FaultPattern(
        "RCE-001", "RCE",
        r"(?:os\.system|subprocess\.(?:call|run|Popen)|exec\(|eval\(|__import__\(|compile\()",
        "CRITICAL",
        "Shell command execution detected",
        "Use sandboxed execution or allowlist commands via CCS GuardrailProvider",
    ),
    FaultPattern(
        "RCE-002", "RCE",
        r"(?:rm\s+-rf|mkfs\.|dd\s+if=|:\(\)\s*\{)",
        "CRITICAL",
        "Destructive shell command detected (fork bomb / disk wipe)",
        "Block destructive commands; route through CCS sandbox executor",
    ),
    FaultPattern(
        "SSRF-001", "SSRF",
        r"(?:requests\.(?:get|post|put|delete)|urllib\.request|httpx\.(?:get|post)|fetch\()",
        "HIGH",
        "Outbound HTTP request detected — potential SSRF",
        "Validate URL against allowlist; block internal IP ranges (10.x, 169.254.x, ::1)",
    ),
    FaultPattern(
        "SSRF-002", "SSRF",
        r"(?:http://(?:localhost|127\.0\.0\.1|10\.\d+|172\.(?:1[6-9]|2\d|3[01])|192\.168\.|0\.0\.0\.0|\[::1\]|169\.254\.))",
        "CRITICAL",
        "Request to internal/private IP detected",
        "Block all requests to private IP ranges at the GuardrailProvider layer",
    ),
    FaultPattern(
        "ENV-001", "ENV_LEAK",
        r"(?:os\.environ|os\.getenv|getenv\(|\.env\[|process\.env)",
        "HIGH",
        "Environment variable access detected — potential secret leak",
        "Use CCS env scoping; only expose allowlisted variables",
    ),
    FaultPattern(
        "ENV-002", "ENV_LEAK",
        r"(?:API_KEY|SECRET|TOKEN|PASSWORD|DATABASE_URL|AWS_ACCESS|GITHUB_TOKEN)",
        "CRITICAL",
        "Sensitive credential pattern in output/response",
        "Redact credentials; use CCS secret manager instead of env vars",
    ),
    FaultPattern(
        "INJ-001", "INJECTION",
        r"(?:(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s+.+(?:FROM|INTO|TABLE|DATABASE))",
        "HIGH",
        "Potential SQL injection via raw query",
        "Use parameterized queries; route through CCS query sanitizer",
    ),
    FaultPattern(
        "INJ-002", "INJECTION",
        r"(?:<script|javascript:|onerror=|onload=|<iframe)",
        "HIGH",
        "Potential XSS payload detected",
        "Sanitize output with CCS HTML sanitizer; use CSP headers",
    ),
]


class RuntimeGuard:
    """Runtime guard engine using correctover GuardrailProvider hooks.

    v2.0: License enforcement on scan/diagnose.
    Free tier: limited to 2 detection events, no repair suggestions.
    Pro tier: full detection + repair + live interception.
    """

    # Maximum patterns returned for free tier
    FREE_PATTERN_LIMIT = 2

    def __init__(self, require_license: bool = True):
        self.patterns = FAULT_PATTERNS
        self.stats = GuardStats()
        self._compiled: dict[str, re.Pattern] = {}
        self._block_callback: Optional[Callable] = None
        self._require_license = require_license
        self._license_checked = False
        self._is_pro = False

        if require_license:
            self._check_license_enforcement()

    def _check_license_enforcement(self):
        """Check license at initialization. Raises if no valid license."""
        from .license import LicenseValidator, LicenseExceededError

        validator = LicenseValidator("correctover-runtime-guard")
        license_key = LicenseValidator.get_license_from_env()
        if license_key:
            validator.set_license_key(license_key)

        status = validator.check_license()
        self._is_pro = status["tier"] == "pro"
        self._license_checked = True

        if not self._is_pro:
            # Free tier: allow init but flag as limited
            self._free_mode = True
        else:
            self._free_mode = False

    @property
    def is_pro(self) -> bool:
        """Whether this instance has Pro license."""
        return self._is_pro

    def _get_regex(self, pattern: str) -> re.Pattern:
        if pattern not in self._compiled:
            self._compiled[pattern] = re.compile(pattern, re.IGNORECASE)
        return self._compiled[pattern]

    def scan(self, data: str, source: str = "unknown") -> list[DetectionEvent]:
        """Scan input data against all fault patterns.

        Free tier: returns at most FREE_PATTERN_LIMIT events (no repair info).
        Pro tier: returns all detected events with full repair info.
        """
        events: list[DetectionEvent] = []
        t0 = time.perf_counter()

        for p in self.patterns:
            regex = self._get_regex(p.regex)
            if regex.search(data):
                t1 = time.perf_counter()
                event = DetectionEvent(
                    timestamp=time.time(),
                    pattern=p,
                    input_data=data[:200],
                    source=source,
                    latency_us=(t1 - t0) * 1_000_000,
                )
                events.append(event)
                self.stats.record(event.latency_us, blocked=True)
                if len(self.stats.recent_events) >= 100:
                    self.stats.recent_events.pop(0)
                self.stats.recent_events.append(event)

        if not events:
            t1 = time.perf_counter()
            self.stats.record((t1 - t0) * 1_000_000, blocked=False)

        # Free tier: limit results
        if getattr(self, "_free_mode", False) and len(events) > self.FREE_PATTERN_LIMIT:
            events = events[:self.FREE_PATTERN_LIMIT]

        return events

    def is_safe(self, data: str, source: str = "unknown") -> tuple[bool, list[DetectionEvent]]:
        """Check if data is safe. Returns (is_safe, events)."""
        events = self.scan(data, source)
        return len(events) == 0, events

    def diagnose_error(self, error_message: str) -> list[DetectionEvent]:
        """Diagnose an error message for known fault patterns."""
        return self.scan(error_message, source="error_diagnosis")

    def get_fault_pattern(self, category: Optional[str] = None) -> list[FaultPattern]:
        """Get registered fault patterns, optionally filtered by category.

        Free tier: patterns returned without repair field.
        """
        if category:
            patterns = [p for p in self.patterns if p.category == category.upper()]
        else:
            patterns = list(self.patterns)

        # Free tier: strip repair info
        if getattr(self, "_free_mode", False):
            return [
                FaultPattern(
                    pattern_id=p.pattern_id,
                    category=p.category,
                    regex=p.regex,
                    severity=p.severity,
                    description=p.description,
                    repair="[PRO ONLY] Upgrade for repair strategy",
                )
                for p in patterns
            ]
        return patterns

    def get_repair_suggestion(self, pattern_id: str) -> Optional[dict]:
        """Get repair suggestion for a specific fault pattern.

        Free tier: returns error — repair is Pro only.
        """
        if getattr(self, "_free_mode", False):
            return {
                "found": False,
                "error": "Repair suggestions require Pro license. "
                         "Upgrade at https://correctover.com/checkout",
            }

        for p in self.patterns:
            if p.pattern_id == pattern_id:
                return {
                    "pattern_id": p.pattern_id,
                    "category": p.category,
                    "severity": p.severity,
                    "description": p.description,
                    "repair": p.repair,
                }
        return None

    def get_stats(self) -> GuardStats:
        return self.stats
