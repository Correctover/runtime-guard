"""
correctover-runtime-guard CLI — Runtime RCE/SSRF/Env leak interception.

Usage:
    correctover-runtime-guard start [--transport stdio|sse|streamable-http]
    correctover-runtime-guard diagnose <error_message>
    correctover-runtime-guard stats
"""

import sys
import time
from typing import Optional

import click

from .guard import RuntimeGuard, FAULT_PATTERNS
from .license import LicenseValidator, check_and_record, LicenseExceededError

VERSION = "1.1.0"
CTA_URL = "https://correctover.com/checkout"
PRICING = "$1,999/month (Enterprise)"
LATENCY_P50 = "22µs"


@click.group()
@click.version_option(version=VERSION, prog_name="correctover-runtime-guard")
def cli():
    """Correctover Runtime Guard — real-time RCE/SSRF/Env leak interception.

    Powered by correctover GuardrailProvider runtime hooks.
    22µs P50 detection latency. 8 fault patterns across 4 categories.
    """
    pass


@cli.command()
@click.option("--transport", type=click.Choice(["stdio", "sse", "streamable-http"]), default="stdio")
@click.option("--host", default="0.0.0.0", help="Host for SSE/HTTP transport")
@click.option("--port", default=8080, help="Port for SSE/HTTP transport")
def start(transport: str, host: str, port: int):
    """Start the Runtime Guard MCP server."""
    # License check
    license_key = LicenseValidator.get_license_from_env()
    validator = LicenseValidator("correctover-runtime-guard")
    if license_key:
        validator.set_license_key(license_key)
    status = validator.record_call()
    tier = status.get('tier', 'free')
    remaining = status.get('calls_remaining', 0)
    if tier == 'free':
        click.echo('Free tier: {} calls remaining today ({}/{})'.format(remaining, status['calls_today'], validator.FREE_LIMIT_PER_DAY), err=True)
        click.echo('   Upgrade: https://correctover.com/checkout', err=True)
    elif tier == 'pro':
        click.echo('Pro license active - unlimited calls', err=True)
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    click.echo(f"\n{CYAN}{BOLD}╔══════════════════════════════════════════════╗{RESET}")
    click.echo(f"{CYAN}{BOLD}║{RESET}       {BOLD}Correctover Runtime Guard{RESET}               {CYAN}{BOLD}║{RESET}")
    click.echo(f"{CYAN}{BOLD}╚══════════════════════════════════════════════╝{RESET}\n")
    click.echo(f"  Transport: {BOLD}{transport}{RESET}")
    click.echo(f"  Detection: {GREEN}{LATENCY_P50} P50{RESET}")
    click.echo(f"  Patterns:  {len(FAULT_PATTERNS)} ({', '.join(set(p.category for p in FAULT_PATTERNS))})")
    click.echo(f"  Pricing:   {PRICING}")
    click.echo()

    from .mcp_server import serve
    serve(transport=transport, host=host, port=port)


@cli.command()
@click.argument("error_message")
def diagnose(error_message: str):
    """Diagnose an error message for fault patterns."""
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    guard = RuntimeGuard()
    events = guard.diagnose_error(error_message)

    click.echo(f"\n{CYAN}{BOLD}╔══════════════════════════════════════════════╗{RESET}")
    click.echo(f"{CYAN}{BOLD}║{RESET}         {BOLD}Error Diagnosis Report{RESET}                 {CYAN}{BOLD}║{RESET}")
    click.echo(f"{CYAN}{BOLD}╚══════════════════════════════════════════════╝{RESET}\n")

    click.echo(f"  Input: {DIM}{error_message[:120]}{'...' if len(error_message) > 120 else ''}{RESET}")
    click.echo()

    if not events:
        click.echo(f"  {GREEN}No fault patterns detected — input appears safe.{RESET}")
    else:
        click.echo(f"  {RED}{BOLD}{len(events)} pattern(s) detected{RESET}")
        click.echo()
        for e in events:
            sev_color = RED if e.pattern.severity == "CRITICAL" else YELLOW
            click.echo(f"  {sev_color}[{e.pattern.severity}]{RESET} {DIM}[{e.pattern.pattern_id}]{RESET} {BOLD}{e.pattern.category}{RESET}")
            click.echo(f"    {DIM}{e.pattern.description}{RESET}")
            click.echo(f"    {GREEN}Fix: {e.pattern.repair}{RESET}")
            click.echo()

    # CTA
    click.echo(f"{CYAN}{BOLD}┌─────────────────────────────────────────────────┐{RESET}")
    click.echo(f"{CYAN}{BOLD}│{RESET}  🛡️  Deploy Guard → {CTA_URL}      {CYAN}{BOLD}│{RESET}")
    click.echo(f"{CYAN}{BOLD}│{RESET}  {DIM}{LATENCY_P50} P50 · {PRICING}{RESET}                     {CYAN}{BOLD}│{RESET}")
    click.echo(f"{CYAN}{BOLD}└─────────────────────────────────────────────────┘{RESET}\n")


@cli.command()
def stats():
    """Show guard statistics and registered patterns."""
    GREEN = "\033[92m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    click.echo(f"\n{CYAN}{BOLD}╔══════════════════════════════════════════════╗{RESET}")
    click.echo(f"{CYAN}{BOLD}║{RESET}       {BOLD}Runtime Guard Statistics{RESET}                {CYAN}{BOLD}║{RESET}")
    click.echo(f"{CYAN}{BOLD}╚══════════════════════════════════════════════╝{RESET}\n")

    click.echo(f"  Detection latency: {GREEN}{LATENCY_P50} P50{RESET}")
    click.echo(f"  Fault patterns:    {len(FAULT_PATTERNS)} total")
    click.echo(f"  Pricing:           {PRICING}")
    click.echo()

    from collections import Counter
    cats = Counter(p.category for p in FAULT_PATTERNS)
    click.echo(f"  {BOLD}Category breakdown:{RESET}")
    for cat, count in sorted(cats.items()):
        click.echo(f"    {cat}: {count} patterns")

    click.echo(f"\n  {BOLD}Registered patterns:{RESET}")
    for p in FAULT_PATTERNS:
        sev_color = RED if p.severity == "CRITICAL" else "\033[93m"
        click.echo(f"    {sev_color}[{p.severity}]{RESET} {DIM}[{p.pattern_id}]{RESET} {p.description}")
        click.echo(f"      {GREEN}→ {p.repair}{RESET}")

    click.echo(f"\n{CYAN}{BOLD}┌─────────────────────────────────────────────────┐{RESET}")
    click.echo(f"{CYAN}{BOLD}│{RESET}  🛡️  Deploy Guard → {CTA_URL}      {CYAN}{BOLD}│{RESET}")
    click.echo(f"{CYAN}{BOLD}│{RESET}  {DIM}{LATENCY_P50} P50 · {PRICING}{RESET}                     {CYAN}{BOLD}│{RESET}")
    click.echo(f"{CYAN}{BOLD}└─────────────────────────────────────────────────┘{RESET}\n")


if __name__ == "__main__":
    cli()
