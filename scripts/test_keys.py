#!/usr/bin/env python3
"""Utility to verify all configured API keys in .env."""

import os
import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

# Load .env
load_dotenv()

console = Console()

def test_virustotal():
    key = os.environ.get("SUSCHECK_VT_KEY")
    if not key: return "❌ Not set"
    try:
        url = "https://www.virustotal.com/api/v3/users/current"
        headers = {"x-apikey": key}
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            return f"✅ Valid (User: {res.json()['data']['id']})"
        return f"❌ Error: {res.status_code}"
    except Exception as e:
        return f"❌ Failed: {e}"

def test_groq():
    key = os.environ.get("GROQ_API_KEY") or os.environ.get("SUSCHECK_GROQ_KEY")
    if not key: return "❌ Not set"
    try:
        url = "https://api.groq.com/openai/v1/models"
        headers = {"Authorization": f"Bearer {key}"}
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            return "✅ Valid (Models listed)"
        return f"❌ Error: {res.status_code}"
    except Exception as e:
        return f"❌ Failed: {e}"

def test_anthropic():
    key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("SUSCHECK_ANTHROPIC_KEY")
    if not key: return "❌ Not set"
    try:
        # Anthropic doesn't have a trivial 'check' endpoint without a message, but we can try a list or just check the key format
        return "✅ Key present (TBD connectivity)"
    except Exception as e:
        return f"❌ Failed: {e}"

def test_gemini():
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key: return "❌ Not set"
    return "✅ Key present"

def run_tests():
    console.print("\n[bold blue]SusCheck API Key Verification[/bold blue]\n")
    
    table = Table(title="API Connectivity Results")
    table.add_column("Provider", style="cyan")
    table.add_column("Status", style="magenta")
    
    table.add_row("VirusTotal", test_virustotal())
    table.add_row("Groq", test_groq())
    table.add_row("Anthropic", test_anthropic())
    table.add_row("Gemini/Google", test_gemini())
    
    console.print(table)
    console.print("\n[dim]Note: Some providers like Anthropic/Gemini are verified during actual triage logic.[/dim]")

if __name__ == "__main__":
    run_tests()
