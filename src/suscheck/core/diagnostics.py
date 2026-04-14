"""Diagnostic Suite for SusCheck API Keys and Services."""

import requests
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

from suscheck.core.config_manager import ConfigManager
from suscheck.core.errors import DiagnosticCheckError

logger = logging.getLogger(__name__)

@dataclass
class DiagnosticResult:
    service: str
    status: str  # "OK", "FAILED", "SKIPPED", "AUTH_ERROR", "RATE_LIMITED"
    message: str
    details: Optional[Dict] = None

class DiagnosticSuite:
    """Validates connectivity and authentication for all configured services."""

    def __init__(self, config: ConfigManager):
        self.config = config
        self.results: List[DiagnosticResult] = []

    def run_all(self) -> List[DiagnosticResult]:
        """Runs diagnostics for all enabled services."""
        self.results = []
        
        # 1. VirusTotal
        self._check_virustotal()
        
        # 2. AbuseIPDB
        self._check_abuseipdb()
        
        # 3. GitHub
        self._check_github()
        
        # 4. NVD
        self._check_nvd()
        
        # 5. AI Providers
        self._check_ai_providers()
        
        return self.results

    def _check_virustotal(self):
        key = self.config.get("api_keys.virustotal")
        if not key:
            self.results.append(DiagnosticResult("VirusTotal", "SKIPPED", "No API key configured"))
            return

        try:
            # Check EICAR hash (standard benign test)
            url = "https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            headers = {"x-apikey": key}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                self.results.append(DiagnosticResult("VirusTotal", "OK", "Successfully authenticated and queried"))
            elif response.status_code in (401, 403):
                self.results.append(DiagnosticResult("VirusTotal", "AUTH_ERROR", "Invalid API key"))
            elif response.status_code == 429:
                self.results.append(DiagnosticResult("VirusTotal", "RATE_LIMITED", "Free tier limit reached or temporarily blocked"))
            else:
                self.results.append(DiagnosticResult("VirusTotal", "FAILED", f"Status Code: {response.status_code}"))
        except requests.RequestException as e:
            err = DiagnosticCheckError(str(e), code="DIAG_VIRUSTOTAL_REQUEST_FAILED")
            self.results.append(
                DiagnosticResult("VirusTotal", "FAILED", str(err), details={"error_code": err.code})
            )

    def _check_abuseipdb(self):
        key = self.config.get("api_keys.abuseipdb")
        if not key:
            self.results.append(DiagnosticResult("AbuseIPDB", "SKIPPED", "No API key configured"))
            return

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": key, "Accept": "application/json"}
            params = {"ipAddress": "8.8.8.8"}
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                self.results.append(DiagnosticResult("AbuseIPDB", "OK", "Successfully authenticated and queried"))
            elif response.status_code == 401:
                self.results.append(DiagnosticResult("AbuseIPDB", "AUTH_ERROR", "Invalid API key"))
            elif response.status_code == 429:
                self.results.append(DiagnosticResult("AbuseIPDB", "RATE_LIMITED", "Daily limit reached"))
            else:
                self.results.append(DiagnosticResult("AbuseIPDB", "FAILED", f"Status Code: {response.status_code}"))
        except requests.RequestException as e:
            err = DiagnosticCheckError(str(e), code="DIAG_ABUSEIPDB_REQUEST_FAILED")
            self.results.append(
                DiagnosticResult("AbuseIPDB", "FAILED", str(err), details={"error_code": err.code})
            )

    def _check_github(self):
        key = self.config.get("api_keys.github_token")
        if not key:
            self.results.append(DiagnosticResult("GitHub", "SKIPPED", "No Token configured"))
            return

        try:
            url = "https://api.github.com/user"
            headers = {"Authorization": f"Bearer {key}", "Accept": "application/vnd.github+json"}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                user_data = response.json()
                login = user_data.get("login", "unknown")
                self.results.append(DiagnosticResult("GitHub", "OK", f"Authenticated as user: {login}"))
            elif response.status_code == 401:
                self.results.append(DiagnosticResult("GitHub", "AUTH_ERROR", "Invalid or expired token"))
            else:
                self.results.append(DiagnosticResult("GitHub", "FAILED", f"Status Code: {response.status_code}"))
        except requests.RequestException as e:
            err = DiagnosticCheckError(str(e), code="DIAG_GITHUB_REQUEST_FAILED")
            self.results.append(
                DiagnosticResult("GitHub", "FAILED", str(err), details={"error_code": err.code})
            )

    def _check_nvd(self):
        key = self.config.get("api_keys.nvd")
        # NVD doesn't strictly require a key but it's used for rate limiting
        if not key:
            self.results.append(DiagnosticResult("NVD", "OK", "Running without key (limited rate)"))
            return

        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            headers = {"apiKey": key}
            params = {"cveId": "CVE-2021-44228"} # Log4Shell
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                self.results.append(DiagnosticResult("NVD", "OK", "Successfully authenticated with API key"))
            elif response.status_code == 403:
                self.results.append(DiagnosticResult("NVD", "AUTH_ERROR", "Invalid API key"))
            else:
                self.results.append(DiagnosticResult("NVD", "FAILED", f"Status Code: {response.status_code}"))
        except requests.RequestException as e:
            err = DiagnosticCheckError(str(e), code="DIAG_NVD_REQUEST_FAILED")
            self.results.append(
                DiagnosticResult("NVD", "FAILED", str(err), details={"error_code": err.code})
            )

    def _check_ai_providers(self):
        """Checks the primary AI provider configured in the system."""
        provider_model = self.config.get("ai.primary_model", "")
        if ":" not in provider_model:
            self.results.append(DiagnosticResult("AI Triage", "SKIPPED", "No primary AI provider configured"))
            return

        provider = provider_model.split(":")[0]
        key = self.config.get(f"api_keys.{provider}")
        
        if not key:
            self.results.append(DiagnosticResult(f"AI ({provider})", "SKIPPED", f"No key found for provider '{provider}'"))
            return

        # We'll use a simple HTTP check instead of litellm to keep diagnostics light and isolated
        try:
            if provider == "groq":
                url = "https://api.groq.com/openai/v1/models"
                headers = {"Authorization": f"Bearer {key}"}
                response = requests.get(url, headers=headers, timeout=10)
            elif provider == "anthropic":
                url = "https://api.anthropic.com/v1/messages" # Minimal check
                headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
                response = requests.get(url, headers=headers, timeout=10)
                # 400 is actually "good" because it means we hit the server but didn't provide a body
                if response.status_code in (200, 400):
                    self.results.append(DiagnosticResult(f"AI ({provider})", "OK", "Successfully connected"))
                    return
            elif provider == "gemini":
                url = f"https://generativelanguage.googleapis.com/v1beta/models?key={key}"
                response = requests.get(url, timeout=10)
            else:
                self.results.append(DiagnosticResult(f"AI ({provider})", "OK", "Diagnostic check not implemented for this provider yet"))
                return

            if response.status_code == 200:
                self.results.append(DiagnosticResult(f"AI ({provider})", "OK", "Successfully authenticated"))
            elif response.status_code in (401, 403):
                self.results.append(DiagnosticResult(f"AI ({provider})", "AUTH_ERROR", "Invalid API key"))
            else:
                self.results.append(DiagnosticResult(f"AI ({provider})", "FAILED", f"Status Code: {response.status_code}"))
        except requests.RequestException as e:
            err = DiagnosticCheckError(str(e), code="DIAG_AI_PROVIDER_REQUEST_FAILED")
            self.results.append(
                DiagnosticResult(f"AI ({provider})", "FAILED", str(err), details={"error_code": err.code})
            )
