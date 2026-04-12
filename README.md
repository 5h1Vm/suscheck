# SusCheck (v0.1.0)
### Pre-execution Security Auditing Platform

**SusCheck** is a high-performance security platform designed to audit code, infrastructure (IaC), and third-party artifacts *before* they are executed. By using a multi-tiered analysis engine, SusCheck provides sub-second detection for common threats while orchestrating advanced SAST and AI triage for complex artifacts.

---

## ⚡ Quickstart

### 1. Installation
Set up the entire platform (environment, dependencies, and CLI) with a single command:
```bash
bash setup.sh
```

### 2. Activate & Use
After setup, activate the environment to start scanning:
```bash
source .venv/bin/activate
suscheck scan ./target_dir
```
SusCheck uses a **.env-first** configuration model. Create a `.env` file in the root directory:
```env
# API Keys (Required for reputation/AI lookup)
SUSCHECK_VT_KEY=your_virustotal_key
SUSCHECK_ABUSEIPDB_KEY=your_abuseipdb_key
SUSCHECK_GROQ_KEY=your_groq_key
```

### 3. Usage
```bash
# Scan a directory
suscheck scan ./target_dir

# Scan a single script
suscheck scan malicious_script.py

# Generate a JSON report
suscheck scan --format json --output report.json ./target_project
```

---

## 🏗️ Technical Architecture
SusCheck follows a **3-Tiered Security Pipeline**:

1.  **Tier 1 (Instant Heuristics)**: Static regex-bound analysis for immediate risk identification (0.02s).
2.  **Tier 2 (Advanced Engine)**: Deep auditing via **Semgrep**, **Bandit**, and **Checkov** for IaC security.
3.  **Tier 3 (AI Triage)**: Logical intent analysis powered by Groq/Gemini to reduce false positives.

---

## 📂 Project Structure
For a detailed guide on every folder and file in the repository, see:
👉 **[The Professional Project Index (docs/FILES.md)](docs/FILES.md)**

---

## 🧪 Security Verification
SusCheck includes a curated suite of malicious and benign indicators in `tests/samples/` to help you verify platform rigor and the accuracy of the **Platform Risk Index (PRI)**.

---

**Mission**: Scan Before You Trust.  
**Academic Lead**: USER  
**Contributors**: Antigravity AI  
**License**: MIT / Research
