# 🛡️ SusCheck: Dynamic Pre-Execution Trust Platform

[![Academic Context](https://img.shields.io/badge/NFSU-Minor%20Project-blue)](docs/PROFESSOR_GUIDE.md)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Safety Status](https://img.shields.io/badge/Security-Verified-blueviolet)](audit/18_STEP_AUDIT.md)

**SusCheck** is a high-fidelity security platform designed to audit code, packages, and repositories before execution. It calculates a comprehensive **Platform Risk Index (PRI)** to prevent software supply chain attacks and malicious code execution.

---

## ✨ Key Features

### 🔍 Unified Trust Engine
Orchestrates multiple security layers (Static, Dynamic, and Reputation) into a single, normalized score.
- **Shadow Dependency Detection**: Scans source imports to find undeclared or malicious packages.
- **Typosquat Detection**: Audits package names against popular targets (e.g., `requesrs` vs `requests`).
- **MCP behavioral Observation**: Sandbox-based dynamic analysis for MCP servers.

### 🤖 AI Triage & Explanation
Leverages LLMs (Groq/Ollama) to analyze the semantic context of security findings, drastically reducing false positives and providing human-readable risk summaries.

### ⚖️ Platform Risk Index (PRI)
A weighted scoring algorithm (0-100) that generates a clear verdict:
- ✅ **CLEAR** (0-15): Safe to execute.
- ⚠️ **CAUTION** (16-40): Non-critical issues found.
- ⛔ **HOLD** (41-70): Potentially malicious; manual review required.
- ❌ **ABORT** (71-100): High-confidence threat identified.

---

## 🚀 Quick Start

### 1. Installation
```bash
./setup.sh
source .venv/bin/activate
```

### 2. Basic Usage
Scan a single file or a full repository:
```bash
suscheck scan path/to/your/code.py
```

### 3. Comprehensive Audit
Run with verbose output to see the full "Score Breakdown":
```bash
suscheck scan path/to/project/ --verbose
```

---

## 🎓 Academic Submission
This project is submitted as the **Minor Project II** for **NFSU Delhi**.
- **Professor's Guide**: [docs/PROFESSOR_GUIDE.md](docs/PROFESSOR_GUIDE.md)
- **18-Step Audit Trail**: [audit/18_STEP_AUDIT.md](audit/18_STEP_AUDIT.md)

---
*Created with ❤️ by Shivam Kumar Singh*
