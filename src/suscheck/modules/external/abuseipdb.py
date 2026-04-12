"""AbuseIPDB Client for SusCheck.

Queries the AbuseIPDB API v2 to check IP address reputation.
"""

import logging
import os
import time
from typing import Optional

import requests
from pydantic import BaseModel, Field, ConfigDict

from suscheck.core.finding import Finding, FindingType, Severity

# Standard AbuseIPDB API URL
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_TIMEOUT = 10
logger = logging.getLogger(__name__)

class AbuseIPDBResult(BaseModel):
    """Result from an IP reputation check."""
    model_config = ConfigDict(populate_by_name=True)

    ip_address: str = Field(alias="ipAddress")
    is_public: bool = Field(default=True, alias="isPublic")
    ip_version: int = Field(default=4, alias="ipVersion")
    is_whitelisted: bool = Field(default=False, alias="isWhitelisted")
    abuse_confidence_score: int = Field(default=0, alias="abuseConfidenceScore")
    country_code: Optional[str] = Field(default=None, alias="countryCode")
    usage_type: Optional[str] = Field(default=None, alias="usageType")
    isp: Optional[str] = Field(default=None, alias="isp")
    domain: Optional[str] = Field(default=None, alias="domain")
    hostnames: list[str] = Field(default_factory=list, alias="hostnames")
    total_reports: int = Field(default=0, alias="totalReports")
    num_distinct_users: int = Field(default=0, alias="numDistinctUsers")
    last_reported_at: Optional[str] = Field(default=None, alias="lastReportedAt")


class AbuseIPDBClient:
    """Client for querying AbuseIPDB."""

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the AbuseIPDB client.

        Args:
            api_key: Optional API key. If not provided, pulls from env.
        """
        self.api_key = api_key or os.environ.get("SUSCHECK_ABUSEIPDB_KEY")
        self.is_configured = bool(self.api_key)

    def lookup_ip(self, ip_address: str, max_age_days: int = 90) -> Optional[AbuseIPDBResult]:
        """Look up an IP address on AbuseIPDB.

        Args:
            ip_address: The IPv4 or IPv6 address to check.
            max_age_days: Max age of reports to consider (default 90).

        Returns:
            AbuseIPDBResult if successful, None on error or if not configured.
        """
        if not self.is_configured:
            logger.debug("AbuseIPDB API key not configured, skipping lookup.")
            return None

        headers = {
            "Accept": "application/json",
            "Key": self.api_key,  # type: ignore
        }

        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": str(max_age_days),
            "verbose": ""  # Include verbose data (country, domain etc)
        }

        try:
            start_time = time.time()
            # Send the request
            response = requests.get(
                ABUSEIPDB_API_URL,
                headers=headers,
                params=params,
                timeout=DEFAULT_TIMEOUT,
            )

            # Handle rate limits
            if response.status_code == 429:
                logger.warning("AbuseIPDB API rate limit exceeded.")
                return None
            elif response.status_code == 401:
                logger.error("AbuseIPDB API key is invalid.")
                return None
            
            response.raise_for_status()
            data = response.json().get("data", {})
            duration = time.time() - start_time
            logger.debug(f"AbuseIPDB lookup for {ip_address} took {duration:.2f}s")
            
            return AbuseIPDBResult(**data)

        except requests.RequestException as e:
            logger.warning(f"Error querying AbuseIPDB for {ip_address}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error parsing AbuseIPDB response: {e}")
            return None

    def create_finding(self, result: AbuseIPDBResult, line_number: Optional[int] = None) -> Optional[Finding]:
        """Convert an AbuseIPDB result into a standardized Finding.
        
        Only returns a Finding if the abuse confidence score is > 0.
        """
        if result.abuse_confidence_score <= 0:
            return None

        # Determine severity based on confidence score
        if result.abuse_confidence_score >= 80:
            severity = Severity.CRITICAL
            confidence = 0.95
        elif result.abuse_confidence_score >= 50:
            severity = Severity.HIGH
            confidence = 0.85
        elif result.abuse_confidence_score >= 20:
            severity = Severity.MEDIUM
            confidence = 0.70
        else:
            severity = Severity.LOW
            confidence = 0.50

        title = f"Malicious IP Address: {result.ip_address}"
        description = (
            f"IP address {result.ip_address} is reported as malicious by AbuseIPDB "
            f"with a confidence score of {result.abuse_confidence_score}% "
            f"({result.total_reports} reports)."
        )
        
        if result.country_code:
            description += f" Location: {result.country_code}."
        if result.domain:
            description += f" Domain: {result.domain}."

        return Finding(
            module="abuseipdb",
            finding_id=f"ABUSEIPDB-{result.ip_address.replace('.', '-')}",
            title=title,
            description=description,
            severity=severity,
            finding_type=FindingType.C2_INDICATOR,
            confidence=confidence,
            line_number=line_number,
            mitre_ids=["T1071"], # Application Layer Protocol
            evidence={
                "ip": result.ip_address,
                "abuse_score": result.abuse_confidence_score,
                "total_reports": result.total_reports,
                "country": result.country_code,
                "domain": result.domain,
                "whitelisted": result.is_whitelisted
            }
        )
