# SusCheck: Zero-Trust Pre-Execution Orchestrator

**Audit before you execute.** SusCheck is a professional-grade security utility designed to orchestrate deep forensic analysis of software artifacts (packages, scripts, binaries, and repositories) before they touch your production environment.

[![Security: Zero-Trust](https://img.shields.io/badge/Security-Zero--Trust-red)](registry/CORE_SECURITY_MODEL.md)
[![Status: Gold Master](https://img.shields.io/badge/Status-Gold%20Master-gold)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green)]()

---

## 🛠️ The Mission
Modern software supply chains are compromised by default. From dependency confusion to polyglot masquerading, static analysis is no longer enough. SusCheck provides a **Unified Forensic Brain** that aggregates industry-standard engines (Semgrep, Gitleaks, Checkov) and AI-driven triage to produce a definitive **Platform Risk Index (PRI)**.

## 🚀 Key Forensic Capabilities
- **Multi-Engine Orchestration**: Simultaneous scanning for secrets, vulnerabilities, and IaC misconfigurations.
- **Polyglot & Masquerading Detection**: Identification of MITRE T1036.008 threats (file header/extension mismatches).
- **AI Triage Layer**: Automated indicator correlation and false-positive reduction using fallback-resilient LLM orchestration.
- **Tier 0 Reputation**: Real-time VirusTotal integration and hash reputation checks.
- **Zero-Trust Verdicts**: Hardened deployment recommendations (Clear, Caution, Hold, Abort) based on a weighted 18-step security model.

---

## ⚡ Quickstart

### 1. Initialize Environment
```bash
bash setup.sh
source .venv/bin/activate
```

### 2. Configure Indicators
Configure your `.env` with API keys for enhanced intelligence:
```bash
# AI Provider (SambaNova/Groq/OpenRouter fallback supported)
SUSCHECK_AI_API_KEY=your_key_here

# Threat Intelligence
SUSCHECK_VT_API_KEY=your_key_here

# Scanning Constraints
SUSCHECK_SCANNING_MAX_FILE_SIZE_MB=50
```

### 3. Execute Forensic Scan
```bash
# Scan a local repository
suscheck scan ./target-repo

# Scan a specific file
suscheck scan malware.py

# Explain a specific finding
suscheck explain FINDING_ID
```

---

## 🧠 The Core Security Model
SusCheck operates on a tiered forensic model derived from real-world adversarial tactics.

| Tier | Name | Focus |
| :--- | :--- | :--- |
| **0** | Reputation | Hashes, VT Detections, Known IoCs |
| **1** | Static Audit | Secrets, CVEs, Misconfigurations, Masquerading |
| **2** | AI Triage | Threat Correlation, Behavioral Heuristics |
| **3** | Aggregation | Weighted Scoring (PRI) & Hardened Verdicts |

Read more in the [Core Security Model](registry/CORE_SECURITY_MODEL.md).

---

## 📂 Registry & Documentation
- [Quickstart Guide](docs/Quickstart.md): Deep dive into CLI usage and configuration.
- [Developer Reference](docs/Developer_Reference.md): Architectural overview and per-module documentation.
- [Registry](registry/): Core security logic and stress test reports.

---

**SusCheck** | Developed for the community. Stay paranoid.
