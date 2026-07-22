# 🛡️ correctover-runtime-guard

**Real-time RCE/SSRF/Env Leak interception — 22µs P50.**

[![PyPI version](https://img.shields.io/pypi/v/correctover-runtime-guard.svg)](https://pypi.org/project/correctover-runtime-guard/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

## Quick Start

```bash
pip install correctover-runtime-guard
correctover-runtime-guard start
```

## What It Does

Runtime guardrail for AI Agent tool calls — intercepts before execution:

- **RCE interception** (CWE-78) — command injection in tool arguments
- **SSRF blocking** (CWE-918) — metadata endpoint access, internal port scanning
- **Env leak prevention** (CWE-200) — `AWS_SECRET_ACCESS_KEY`, `OPENAI_API_KEY` exfiltration
- **MCP Server mode** — `diagnose_error` / `get_fault_pattern` / `get_repair_suggestion`

### Performance

| Metric | Value |
|--------|-------|
| P50 latency | 22µs |
| P99 latency | 89µs |
| Overhead | <0.01% |
| Detection rate | 99.7% |

## Free Tier

50 interceptions/day — no credit card required.

Enterprise: $1,999/month — [correctover.com/checkout](https://correctover.com/checkout)

```bash
export CORRECTOVER_LICENSE_KEY=your-key-here
```

## Related Correctover Tools

| Tool | Install | Description |
|------|---------|-------------|
| **Security Scanner** | `npx correctover-scan` | MCP config security audit (14 checks) |
| **Self-Healing Test** | `pip install correctover-test` | Agent self-healing test suite |
| **Vulnerability Scan** | `pip install correctover-security-audit` | 215 fault type scanner |
| **Compliance Check** | `pip install correctover-compliance-check` | OAuth 2.1 + CCS v1.0 |
| **Runtime Guard** | `pip install correctover-runtime-guard` | 22µs RCE/SSRF interception |
| **MCP Server** | `npm install correctover-mcp-server` | 6-dimension validation |

**Website**: [correctover.com](https://correctover.com) · **GitHub**: [github.com/Correctover](https://github.com/Correctover)
