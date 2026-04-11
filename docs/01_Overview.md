# SusCheck Overview

**SusCheck** is a CLI-first, modular, pre-execution security scanning platform designed to scan unverified external artifacts—like cloned repositories, raw scripts, and dynamically downloaded packages—before they are executed on your system.

Unlike traditional Static Application Security Testing (SAST) tools that look for syntax flaws or OWASP vulnerabilities inside your own code (e.g., SQL Injection), SusCheck looks for **threats, malware indicators, and supply chain risks**.

## Why SusCheck?
Many workflows rely on unverified code execution such as:
- `curl http://example.com/install.sh | bash`
- Blindly cloning unknown repositories.
- Reusing or downloading unfamiliar AI-generated logic and scripts.

SusCheck acts as a fast filtering layer to provide actionable intelligence and an absolute risk score (the PRI: Platform Risk Index) to give a definitive "Go/No-Go" status before execution.

## Core Ideology
1. **No Hallucinations:** Use concrete patterns, static rules, and actual cyber-intelligence API lookups first.
2. **Speed is important, but correctness comes first:** The quick-pass hashing (Tier 0) executes in milliseconds, while code scanning (Tier 1) detects the majority of threats within seconds. The system prioritizes accurate detection over marginal speed gains, ensuring reliability without significant performance trade-offs.
3. **Graceful Degradation:** The platform does not break if you're missing an API key or an external integration endpoint. It continues testing what it can.
