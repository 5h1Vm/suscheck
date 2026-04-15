# SusCheck: Zero-Trust Pre-Execution Orchestrator

**SusCheck** is a modular, high-fidelity security orchestration platform designed to audit code, configurations, and supply chains *before* execution. High-performance security for modern DevOps workflows.

> "Don't execute what you haven't audited. Zero-trust starts at the command line."

---

## 🚀 The Core Vision

SusCheck moves security to the **point of intent**. Whether you are cloning a repository, installing a package, or connecting an MCP server, SusCheck acts as an intelligent gatekeeper, calculating a real-time **Platform Risk Index (PRI)** to prevent supply chain compromise and execution of malicious code.

### Platform Key Pillars
1. **Multi-Engine Orchestration**: Unified interface for Semgrep, Bandit, Checkov, KICS, Gitleaks, and OWASP Dependency-Check.
2. **AI-Driven Triage**: Context-aware risk adjustment using advanced LLM analysis (Groq, Anthropic, Gemini).
3. **9-Category Supply Chain Trust**: Deep auditing of package metadata, typosquatting, and registry health.
4. **Recursive Decoding**: Intelligent unwrapping of obfuscated payloads and multi-stage droppers.
5. **Transitive Dependency Chain**: Automated tracking of the entire 'phantom' supply chain.

---

## 🛡️ The 3-Tier Pipeline

SusCheck executes a deterministic 10-step algorithm to derive the PRI:

1.  **Tier 0 (Reputation)**: VirusTotal, AbuseIPDB, and registry-level health checks.
2.  **Tier 1 (Static Analysis)**: Deep scan using Semgrep, Bandit, Checkov/KICS, and optional OWASP Dependency-Check.
3.  **Tier 2 (AI Adjustment)**: Intelligent triage to reduce false positives and identify complex logic bombs.

---

## 🛠️ Usage

### Quick Scan
```bash
# Scan a local directory or file
suscheck scan ./my-project

# Scan a remote repository URL
suscheck scan https://github.com/user/repo
```

### Proactive Installation (Wrapper Mode)
Audit packages before they touch your system.
```bash
suscheck install pip requests
suscheck install npm lodash
```

### Safe Cloning
```bash
suscheck clone https://github.com/unsafe/exploit-poc
```

---

## 📊 Platform Risk Index (PRI)

| Score | Verdict | Action Required |
| :--- | :--- | :--- |
| **0 - 15** | [green]SECURE[/green] | Safe to proceed. |
| **16 - 40** | [yellow]CAUTION[/yellow] | Minor findings. Manual review recommended. |
| **41 - 70** | [orange]HOLD[/orange] | Significant risks detected. Wrapper blocks execution. |
| **71 - 100** | [red]ABORT[/red] | Malicious intent or critical vulnerabilities found. |

---

## ⚙️ Setup & Requirements

### 1. Installation
```bash
git clone https://github.com/shivam/suscheck
cd suscheck
bash setup.sh
```

### 1.1 KICS Local Binary (Script-Only)
`setup.sh` now attempts all of the following automatically:
1. Use `SUSCHECK_KICS_ARCHIVE` if you provide an archive path.
2. Auto-download the latest compatible KICS release binary and install it into `.venv/bin/kics`.
3. Persist `SUSCHECK_KICS_PATH` in `.env` for stable discovery.
4. Only then fall back to Docker runtime if local binary install is not possible.

Manual one-liner (still script-only):
```bash
bash setup.sh
```

Optional explicit archive mode:
```bash
SUSCHECK_KICS_ARCHIVE=/path/to/kics-linux-amd64.tar.gz bash setup.sh
```

### 1.2 OWASP Dependency-Check (Script-Only)
`setup.sh` also attempts all of the following for Dependency-Check:
1. Use `SUSCHECK_DEPCHECK_ARCHIVE` if you provide an archive path.
2. Auto-download the latest Dependency-Check release zip.
3. Install it under `.venv/tools/dependency-check/` and create a `.venv/bin/dependency-check` wrapper.

Optional explicit archive mode:
```bash
SUSCHECK_DEPCHECK_ARCHIVE=/path/to/dependency-check-release.zip bash setup.sh
```

### 2. Mandatory Engines
To reach full orchestration potential, ensure the following are installed (handled by `setup.sh`):
- **Bandit**: Python SAST
- **Checkov**: Infrastructure as Code (IaC) Security
- **OWASP Dependency-Check**: Third-party dependency CVE scanning
- **Semgrep**: General-purpose static analysis
- **Gitleaks**: Secret detection

### 2.1 Dependency CVE Scan Mode
Run repository-level dependency vulnerability checks with OWASP Dependency-Check:
```bash
suscheck scan ./my-project --dependency-check
```

Common combinations:
```bash
# Disable AI and VirusTotal noise, keep dependency CVE analysis
suscheck scan ./my-project --dependency-check --no-ai --no-vt

# MCP-only manifest scan
suscheck scan ./mcp.json --mcp-only --no-ai --no-vt

# MCP static + Docker dynamic observation
suscheck scan ./mcp.json --mcp-only --mcp-dynamic --no-ai --no-vt
```

### 3. API Keys (optional but recommended)
Add these to your `.env` for Tier 0 and Tier 2 capabilities:
- `SUSCHECK_AI_API_KEY`: For AI Triage
- `SUSCHECK_VT_API_KEY`: For VirusTotal Reputation

---

## 🤝 Contributing
SusCheck is built for the security community. We prioritize accuracy, speed, and transparency.

**Note**: This project is strictly for security research and pre-execution auditing. Always use in compliance with local regulations.
