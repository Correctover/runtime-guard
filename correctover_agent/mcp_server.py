"""
MCP Server — expose Runtime Guard as MCP tools.
Tools: diagnose_error, get_fault_pattern, get_repair_suggestion

v2.0: License enforcement — repair and live interception are Pro-only.
Free tier gets limited diagnostics (first 2 patterns, no repair).
"""

from typing import Optional

try:
    from fastmcp import FastMCP
    HAS_FASTMCP = True
except ImportError:
    HAS_FASTMCP = False

from .guard import RuntimeGuard
from .license import LicenseValidator


def _get_guard() -> RuntimeGuard:
    """Create a license-aware RuntimeGuard instance."""
    validator = LicenseValidator("correctover-runtime-guard")
    license_key = LicenseValidator.get_license_from_env()
    if license_key:
        validator.set_license_key(license_key)

    status = validator.check_license()
    is_pro = status["tier"] == "pro"

    # Create guard with license awareness
    guard = RuntimeGuard(require_license=False)
    guard._free_mode = not is_pro
    guard._is_pro = is_pro
    return guard


if HAS_FASTMCP:
    mcp = FastMCP("correctover-runtime-guard")

    @mcp.tool()
    def diagnose_error(error_message: str) -> dict:
        """Diagnose an error message for known fault patterns (RCE/SSRF/Env leak/Injection).

        Free tier: returns at most 2 patterns, no repair info.
        Pro tier: returns all detected patterns with full repair.

        Args:
            error_message: The error message or stack trace to analyze.

        Returns:
            dict with 'events' list of detected patterns and 'tier' info.
        """
        guard = _get_guard()
        events = guard.diagnose_error(error_message)

        result_events = []
        for e in events:
            event_dict = {
                "pattern_id": e.pattern.pattern_id,
                "category": e.pattern.category,
                "severity": e.pattern.severity,
                "description": e.pattern.description,
                "source": e.source,
                "latency_us": e.latency_us,
            }
            # Only include repair for Pro
            if guard.is_pro:
                event_dict["repair"] = e.pattern.repair
            else:
                event_dict["repair"] = None  # Pro-only
            result_events.append(event_dict)

        return {
            "events": result_events,
            "total": len(events),
            "tier": "pro" if guard.is_pro else "free",
            "hidden_count": max(0, len(guard.scan(error_message)) - len(events)) if not guard.is_pro else 0,
        }

    @mcp.tool()
    def get_fault_pattern(category: Optional[str] = None) -> dict:
        """Get registered fault patterns, optionally filtered by category.

        Free tier: patterns returned WITHOUT repair field.
        Pro tier: full pattern details including repair.

        Args:
            category: Optional filter — RCE, SSRF, ENV_LEAK, or INJECTION.

        Returns:
            dict with 'patterns' list and 'tier' info.
        """
        guard = _get_guard()
        patterns = guard.get_fault_pattern(category)

        return {
            "patterns": [
                {
                    "pattern_id": p.pattern_id,
                    "category": p.category,
                    "severity": p.severity,
                    "description": p.description,
                    "repair": p.repair if guard.is_pro else None,
                }
                for p in patterns
            ],
            "total": len(patterns),
            "tier": "pro" if guard.is_pro else "free",
        }

    @mcp.tool()
    def get_repair_suggestion(pattern_id: str) -> dict:
        """Get repair suggestion for a specific fault pattern. PRO REQUIRED.

        Args:
            pattern_id: The fault pattern ID (e.g. RCE-001, SSRF-001, ENV-001).

        Returns:
            dict with pattern details and repair guidance, or error if not Pro/not found.
        """
        guard = _get_guard()

        if not guard.is_pro:
            return {
                "found": False,
                "error": "Repair suggestions require Pro license. "
                         "Upgrade at https://correctover.com/checkout",
                "tier": "free",
            }

        suggestion = guard.get_repair_suggestion(pattern_id)
        if suggestion:
            return {"found": True, "tier": "pro", **suggestion}
        return {"found": False, "error": f"Pattern '{pattern_id}' not found", "tier": "pro"}


def serve(transport: str = "stdio", host: str = "0.0.0.0", port: int = 8080):
    """Start the MCP server with the given transport.

    NOTE: MCP server requires Pro license. Call _require_pro() before serve().
    """
    if not HAS_FASTMCP:
        print("Error: fastmcp not installed. Run: pip install fastmcp")
        return

    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport == "sse":
        mcp.run(transport="sse", host=host, port=port)
    elif transport == "streamable-http":
        mcp.run(transport="streamable-http", host=host, port=port)
    else:
        print(f"Error: Unknown transport '{transport}'. Use stdio, sse, or streamable-http.")
