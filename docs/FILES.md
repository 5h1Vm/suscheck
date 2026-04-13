# SusCheck: Forensic File Index & Architecture Manual

This document provides a comprehensive, deep-dive explanation of every file and logic block in the SusCheck Security Platform. It serves as the primary technical reference for forensic analysis and academic review.

---

## 🏛️ Project Hub (Root)
*   `setup.sh`: **The "One True Setup"**. A robust bash script that initializes the virtual environment, handles dependency resolution, restores missing binaries (KICS), and performs an initial platform diagnostic.
*   `requirements.txt`: Manages the hardened dependencies (Typer, Rich, Semgrep, Checkov, Groq, Hashing libraries).
*   `pyproject.toml`: Defines the build system and registers the `suscheck` CLI command for system-wide access.
*   `.env`: The decentralized configuration store. Used for API secrets (VirusTotal, AbuseIPDB, GitHub) to keep them out of the source code.

---

## 🧠 Core Intelligence (`src/suscheck/core/`)
These files contain the platform's primary decision-making logic.

*   `auto_detector.py`: **Layer 0 (Detection)**. Uses magic bytes (via `python-magic`) and shebang analysis to identify file types (Python, JS, Batch, PHP) regardless of their extension. Prevents extension-masquerading attacks.
*   `pipeline.py`: **The Orchestrator**. Implements the 3-tiered scan logic. It manages recursive directory traversal and ensures that every file is fed to the correct scanner (Code, Config, or MCP).
*   `risk_aggregator.py`: **The Brain**. Implements the **10-step PRI scoring algorithm**. It takes raw findings from all modules and calculates a final risk score (0-100) based on severity, confidence, and AI feedback.
*   `finding.py`: **Data Model**. Defines the unified `Finding` object, which maps all security issues to MITRE ATT&CK IDs, severity levels, and evidential snippets.
*   `config_manager.py`: **Settings Hub**. Enables dynamic runtime configuration. It prioritizes system environment variables over `.env` settings for secure CI/CD integration.
*   `diagnostics.py`: **Forensic Health**. Verifies connectivity to external APIs and confirms that all required scanning binaries are in the system path.

---

## 🔍 Security Scan Modules (`src/suscheck/modules/`)
Sub-engines specialized in different attack vectors.

### **1. Code Analysis (`modules/code/`)**
*   `scanner.py`: Tier 1 Static Engine. Orchestrates regex patterns and YARA-style rules across multiple languages.
*   `decoder.py`: **Recursive Decoder**. De-obfuscates nested Base64, Hex, and URL-encoded payloads frequently found in stage-2 malware.
*   `layer2/`: Contains TOML-based language definitions that provide language-specific heuristics for the Layer 1 scanner.

### **2. Infrastructure Audit (`modules/config/`)**
*   `scanner.py`: Orchestrates **Checkov** and **KICS** for IaC auditing (Docker, Terraform, K8s).
*   `checkov_orchestrator.py`: Maps complex Checkov JSON outputs into the platform's simplified `Finding` model.

### **3. Supply Chain Security (`modules/supply_chain/`)**
*   `trust_engine.py`: **The Trust-Audit**. Queries `deps.dev` and `OSV` to track typosquatting, dependency confusion, and maintainer reputation.
*   `auditor.py`: Parses dependency manifests (`requirements.txt`, `pyproject.toml`) and triggers bulk trust audits for the entire project tree.

### **4. Repository Forensics (`modules/repo/`)**
*   `scanner.py`: High-level repository health analyzer. Checks for sensitive files (secrets) and dangerous repo states.
*   `gitleaks_runner.py`: Orchestrates **Gitleaks** to detect leaked API keys, tokens, and hardcoded private certificates in the Git history.

---

### **5. AI Triage & Logic (`src/suscheck/ai/`)**
*   `triage_engine.py`: **AI Guard**. Uses LLMs (Llama 3, Gemini) to analyze findings and decrease the PRI score for false positives, ensuring only high-signal alerts reach the forensic analyst.
*   `explain_engine.py`: **Interactive Tutor**. Provides a plain-English behavioral narrative of what a suspected malicious file is actually doing.

---

## 🧪 Forensic Samples (`../suscheck_tests/`)
Isolated environment for testing.
*   `samples/malicious/`: Contains curated indicators of compromise (C2 beacons, reverse shells).
*   `samples/benign/`: Control group of safe files.
*   `Audits/`: (External) Stores formal verification reports and PRI accuracy logs.

---

**Lead Researcher**: Shivam Kumar Singh (NFSU)  
**Platform Version**: v1.0.0 (Gold)  
**Ship Status**: PRODUCTION READY
