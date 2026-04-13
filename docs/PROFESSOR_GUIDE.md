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

Refer to `audit/18_STEP_AUDIT.md` for a detailed mapping of technical requirements to implementation files.
