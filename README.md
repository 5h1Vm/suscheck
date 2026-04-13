# SusCheck (v1.0.0 Gold)
### Pre-execution Security Auditing Platform
**Lead Researcher**: Shivam Kumar Singh (NFSU Delhi)  
**Academic Affiliation**: National Forensic Sciences University  

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

## 📈 v1.0.0 Compliance Matrix (18 Steps)

| Step | Design Goal | Status | Implementation File |
| :--- | :--- | :--- | :--- |
| **0** | Project Skeleton | ✅ | `pyproject.toml`, `src/suscheck/` |
| **1** | Auto-Detector | ✅ | `core/auto_detector.py` |
| **2** | Finding Model + Rich UI | ✅ | `core/finding.py`, `modules/reporting/` |
| **3** | Tier 0: Hash + VT | ✅ | `modules/external/virustotal.py` |
| **4** | Code Scanner L1 | ✅ | `modules/code/scanner.py` |
| **5** | Recursive Decoder | ✅ | `modules/code/decoder.py` |
| **6** | Language Plugins L2 | ✅ | `modules/code/layer2/*.toml` |
| **7** | Basic PRI Scoring | ✅ | `core/risk_aggregator.py` |
| **8** | Config/IaC Scanner | ✅ | `modules/config/scanner.py` |
| **9** | Supply Chain Trust | ✅ | `modules/supply_chain/trust_engine.py` |
| **10** | Repository Scanner | ✅ | `modules/repo/scanner.py` |
| **11** | MCP Static Scanner | ✅ | `modules/mcp/scanner.py` |
| **12** | MCP Dynamic (Docker) | ✅ | `modules/mcp/dynamic.py` |
| **13** | AI Triage Layer | ✅ | `ai/triage_engine.py` |
| **14** | Full PRI Scoring | ✅ | `core/risk_aggregator.py` (10-Step) |
| **15** | Wrapper Modes | ✅ | `cli.py` (install/clone/connect) |
| **16** | HTML/MD Reports | ✅ | `core/reporter.py` |
| **17** | AI Explain Mode | ✅ | `ai/explain_engine.py` |
| **18** | Final Polish | 🚀 | `setup.sh`, `scripts/` |

---

## 🧪 Security Verification
SusCheck has been externalized from its test indicators to ensure clean production audits. The curated suite of malicious and benign indicators is located in `../suscheck_tests/` to help verify platform rigor.

---

**Mission**: Scan Before You Trust.  
**Academic Lead**: USER  
**Contributors**: Antigravity AI  
**License**: MIT / Research
