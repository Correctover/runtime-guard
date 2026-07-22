"""
MCP Server — expose Runtime Guard as MCP tools.
Tools: diagnose_error, get_fault_pattern, get_repair_suggestion
"""

from typing import Optional

try:
    from fastmcp import FastMCP
    HAS_FASTMCP = True
except ImportError:
    HAS_FASTMCP = False

from .guard import RuntimeGuard

guard = RuntimeGuard()

if HAS_FASTMCP:
    mcp = FastMCP("correctover-runtime-guard")

    @mcp.tool()
    def diagnose_error(error_message: str) -> dict:
        """Diagnose an error message for known fault patterns (RCE/SSRF/Env leak/Injection).

        Args:
            error_message: The error message or stack trace to analyze.

        Returns:
            dict with 'events' list of detected patterns, each containing
            pattern_id, category, severity, description, and repair suggestion.
        """
        events = guard.diagnose_error(error_message)
        return {
            "events": [
                {
                    "pattern_id": e.pattern.pattern_id,
                    "category": e.pattern.category,
                    "severity": e.pattern.severity,
                    "description": e.pattern.description,
                    "repair": e.pattern.repair,
                    "source": e.source,
                    "latency_us": e.latency_us,
                }
                for e in events
            ],
            "total": len(events),
        }

    @mcp.tool()
    def get_fault_pattern(category: Optional[str] = None) -> dict:
        """Get registered fault patterns, optionally filtered by category.

        Args:
            category: Optional filter — RCE, SSRF, ENV_LEAK, or INJECTION.

        Returns:
            dict with 'patterns' list of fault pattern definitions.
        """
        patterns = guard.get_fault_pattern(category)
        return {
            "patterns": [
                {
                    "pattern_id": p.pattern_id,
                    "category": p.category,
                    "severity": p.severity,
                    "description": p.description,
                    "repair": p.repair,
                }
                for p in patterns
            ],
            "total": len(patterns),
        }

    @mcp.tool()
    def get_repair_suggestion(pattern_id: str) -> dict:
        """Get repair suggestion for a specific fault pattern.

        Args:
            pattern_id: The fault pattern ID (e.g. RCE-001, SSRF-001, ENV-001).

        Returns:
            dict with pattern details and repair guidance, or error if not found.
        """
        suggestion = guard.get_repair_suggestion(pattern_id)
        if suggestion:
            return {"found": True, **suggestion}
        return {"found": False, "error": f"Pattern '{pattern_id}' not found"}


def serve(transport: str = "stdio", host: str = "0.0.0.0", port: int = 8080):
    """Start the MCP server with the given transport."""
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
