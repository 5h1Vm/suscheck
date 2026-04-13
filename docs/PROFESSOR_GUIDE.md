# SusCheck Security Platform: Professor's Overview

**Project Title**: SusCheck: Dynamic Pre-Execution Trust & Security Platform  
**Student**: Shivam Kumar Singh  
**Institution**: NFSU Delhi  
**Academic Context**: Minor Project II

---

## 1. Executive Summary
SusCheck is a unified security orchestration platform designed to evaluate the "trustworthiness" of code artifacts (scripts, packages, repositories) before execution. Unlike traditional static analysis tools that focus solely on vulnerabilities, SusCheck implements a **Unified Trust Logic** that aggregates signals from multiple layers:
- **Supply Chain Trust**: Typosquatting detection, maintainer metadata, and shadow dependency analysis.
- **Static Analysis (SAST)**: Layered detection using Semgrep (advanced), Bandit (Python), and custom regex-based indicators.
- **Dynamic Analysis**: Containerized behavioral observation of MCP servers.
- **Reputation Intelligence**: VirusTotal and AbuseIPDB integration.

All findings are normalized into a single **Platform Risk Index (PRI)** (0–100), providing a clear "Abort/Clear" verdict for pre-execution gating.

## 2. Technical Innovation: Shadow Dependency Detection
A key contribution of this project is the **Shadow Dependency Detection** engine. Most tools only scan `requirements.txt` or `package.json`. SusCheck scans the **actual source code imports** to identify packages being called that are *missing* from manifest files. This prevents "blind spot" attacks where malicious dependencies are imported directly from PyPI/NPM without being declared in the project metadata.

## 3. Core Architecture
- **Auto-Detector**: Intelligent artifact classification (Code, Config, MCP, Repo).
- **Core Pipeline**: Orchestrates Tier 0 (Reputation), Tier 1 (Static), and Tier 2 (Advanced/Dynamic) modules.
- **Risk Aggregator**: Implements a weighted 10-step algorithm for PRI calculation, including correlation bonuses (e.g., Obfuscation + Network activity triggers a "Staged Attack" bonus).
- **AI Triage**: Uses LLM-based reasoning (Groq/Ollama) to reduce false positives by analyzing the semantic context of findings.

## 4. How to Evaluate
To see the tool in action, run a comprehensive scan:
```bash
./setup.sh
source .venv/bin/activate
suscheck scan <path_to_code_or_repo>
```

## 5. Industry Engine Orchestration
SusCheck is designed as an **Intelligence Orchestrator**. Rather than building primitive checkers from ground up, it leverages industry-standard security engines and provides a unified intelligence layer for scoring and triage.

| Domain | Orchestrated Engine | Purpose |
| :--- | :--- | :--- |
| **Static Analysis (SAST)** | [Semgrep](https://semgrep.dev/) | OWASP Top 10 patterns & Framework-specific flaws |
| **Python Security** | [Bandit](https://github.com/PyCQA/bandit) | Python-specific AST security analysis |
| **Secret Detection** | [Gitleaks](https://github.com/gitleaks/gitleaks) | High-fidelity credential & API key discovery |
| **Cloud/IaC** | [Checkov](https://www.checkov.io/) | Infrastructure-as-Code (Docker/K8s) misconfiguration |
| **Supply Chain** | [OSV-Scanner](https://osv.dev/) | Vulnerability lookup for transitive dependencies |
| **Malware Intel** | [VirusTotal](https://www.virustotal.com/) | Hash-based reputation (70+ AV engines) |
| **Network Intel** | [AbuseIPDB](https://www.abuseipdb.com/) | Real-time IP reputation & blacklist checking |
| **Fingerprinting** | [Libmagic](https://github.com/file/file) | Native binary identification (MIME/Magic) |

The true innovation of SusCheck is the **Unified Forensic Brain** which normalizes findings from all these sources, performs cross-layer correlation, and uses AI-driven triage to produce a single, actionable PRI score.
