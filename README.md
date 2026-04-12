# SusCheck Security Platform

**SusCheck** is a pre-execution security tool designed to identify malware, supply chain risks, and suspicious behaviors in files, packages, and code repositories *before* they are executed or installed.

## 🚀 Key Features

- **Multi-Tiered Analysis**:
    - **Tier 0**: Hash and Reputation checks via VirusTotal.
    - **Tier 1**: Static behavioral analysis (YARA-style regex, credential hunting, obfuscation detection).
    - **Tier 2**: Advanced SAST using Semgrep orchestration.
- **AI Behavioral Analysis**: Use the `explain` command to get plain-English deep-dives into suspicious code using LLMs (Gemini, OpenAI, Anthropic, or local Ollama).
- **Supply Chain Trust Engine**: Calibrated risk assessments for PyPI packages (detecting yanking, abandonment, and typosquatting).
- **Premium Reporting**: Generate dark-mode HTML audit reports, Markdown summaries, or JSON data exports.
- **Secure-by-Default CLI**: A unified Typer-based interface with a Platform Risk Index (PRI) scoring system.

## 📥 Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/suscheck.git
cd suscheck

# Recommended: setup virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e .
```

## 🛠️ Quick Start

```bash
# Scan a file for threats
suscheck scan suspicious_script.py

# Get an AI explanation of what a file is doing
suscheck explain suspicious_script.py

# Generate a premium HTML audit report
suscheck scan suspicious_file.py --format html --output report.html

# Check the trust level of a PyPI package
suscheck trust urllib3
```

## 📚 Documentation

For detailed guides, see the [docs/](docs/) folder:
- [Quickstart User Guide](docs/00_Quickstart_User_Guide.md)
- [Architecture Overview](docs/02_Architecture_and_Code_Structure.md)
- [CLI Reference](docs/03_CLI_Reference.md)
- [Rules Reference](docs/05_Rules_Reference.md)

## 🛡️ Security Philosophy
SusCheck is designed to work in "High-Trust" environments where developer productivity must be balanced with rigorous security gating. It prioritizes **Behavioral Intent** over simple static signatures.
