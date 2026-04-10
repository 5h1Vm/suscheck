"""VirusTotal API v3 client.

Queries VirusTotal for file hash reputation, URL/IP/domain
reputation. Handles rate limiting, missing API keys, and
network errors gracefully.

Design:
  - No API key → returns None (graceful degradation)
  - Rate limited → waits once, retries once, then skips
  - Network error → returns None + logs error
  - Never raises exceptions to the caller
"""

import base64
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# VirusTotal API v3 base URL
VT_API_BASE = "https://www.virustotal.com/api/v3"

# Rate limit: free tier = 4 requests/minute
# We wait 15s on a 429 and retry once
RATE_LIMIT_WAIT = 15

# Request timeout in seconds
REQUEST_TIMEOUT = 30


@dataclass
class VirusTotalResult:
    """Result of a VirusTotal lookup."""

    hash_sha256: str
    detection_count: int
    total_engines: int
    detection_names: list[str] = field(default_factory=list)
    malicious: bool = False
    vt_link: str = ""
    found: bool = False
    scan_date: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    suggested_threat_label: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dict compatible with render_vt_result() in terminal.py."""
        return {
            "hash_sha256": self.hash_sha256,
            "detection_count": self.detection_count,
            "total_engines": self.total_engines,
            "detection_names": self.detection_names,
            "malicious": self.malicious,
            "vt_link": self.vt_link,
            "found": self.found,
            "scan_date": self.scan_date,
            "tags": self.tags,
            "suggested_threat_label": self.suggested_threat_label,
        }


class VirusTotalClient:
    """VirusTotal API v3 client.

    API key resolution order:
      1. Constructor parameter
      2. Environment variable: SUSCHECK_VT_KEY
      3. None (graceful degradation — all lookups return None)

    Usage:
        client = VirusTotalClient()
        result = client.lookup_hash("abc123...")
        if result and result.found:
            print(f"Detections: {result.detection_count}/{result.total_engines}")
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("SUSCHECK_VT_KEY")
        self._session = requests.Session()
        if self.api_key:
            self._session.headers.update({"x-apikey": self.api_key})

    @property
    def available(self) -> bool:
        """Whether the client has an API key configured."""
        return bool(self.api_key)

    def lookup_hash(self, file_hash: str) -> Optional[VirusTotalResult]:
        """Look up a file hash on VirusTotal.

        Args:
            file_hash: SHA-256, MD5, or SHA-1 hash.

        Returns:
            VirusTotalResult if successful, None if unavailable/error.
        """
        if not self.available:
            logger.info("VirusTotal lookup skipped: no API key configured")
            return None

        url = f"{VT_API_BASE}/files/{file_hash}"
        data = self._make_request(url)

        if data is None:
            return VirusTotalResult(
                hash_sha256=file_hash,
                detection_count=0,
                total_engines=0,
                found=False,
            )

        return self._parse_file_response(file_hash, data)

    def lookup_url(self, target_url: str) -> Optional[VirusTotalResult]:
        """Look up a URL on VirusTotal.

        Args:
            target_url: The URL to check.

        Returns:
            VirusTotalResult if successful, None if unavailable/error.
        """
        if not self.available:
            return None

        # VT URL id = base64(url) without padding
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().rstrip("=")
        url = f"{VT_API_BASE}/urls/{url_id}"
        data = self._make_request(url)

        if data is None:
            return None

        return self._parse_url_response(target_url, data)

    def lookup_ip(self, ip_address: str) -> Optional[VirusTotalResult]:
        """Look up an IP address on VirusTotal.

        Args:
            ip_address: IPv4 or IPv6 address.

        Returns:
            VirusTotalResult if successful, None if unavailable/error.
        """
        if not self.available:
            return None

        url = f"{VT_API_BASE}/ip_addresses/{ip_address}"
        data = self._make_request(url)

        if data is None:
            return None

        return self._parse_ip_response(ip_address, data)

    def lookup_domain(self, domain: str) -> Optional[VirusTotalResult]:
        """Look up a domain on VirusTotal.

        Args:
            domain: Domain name to check.

        Returns:
            VirusTotalResult if successful, None if unavailable/error.
        """
        if not self.available:
            return None

        url = f"{VT_API_BASE}/domains/{domain}"
        data = self._make_request(url)

        if data is None:
            return None

        return self._parse_domain_response(domain, data)

    def upload_file(
        self, file_path: str, poll_timeout: int = 120
    ) -> Optional[VirusTotalResult]:
        """Upload a file to VirusTotal for scanning.

        ⚠️  WARNING: Uploaded files become PUBLICLY VISIBLE on VirusTotal.
        This should ONLY be used with explicit user opt-in (--upload-vt flag).

        Args:
            file_path: Path to the file to upload.
            poll_timeout: Max seconds to wait for scan results (default 120).

        Returns:
            VirusTotalResult with scan results, or None on error.
        """
        if not self.available:
            logger.info("VirusTotal upload skipped: no API key configured")
            return None

        # VT free tier: files up to 32 MB via /files endpoint
        # Files 32-650 MB use /files/upload_url (get a special upload URL first)
        import os as _os
        file_size = _os.path.getsize(file_path)
        max_direct = 32 * 1024 * 1024  # 32 MB

        if file_size > max_direct:
            logger.warning(
                f"File too large for VT direct upload ({file_size:,} bytes, "
                f"max {max_direct:,}). Large file upload not yet supported."
            )
            return None

        try:
            logger.info(f"Uploading {file_path} to VirusTotal for scanning...")

            with open(file_path, "rb") as f:
                files = {"file": (_os.path.basename(file_path), f)}
                response = self._session.post(
                    f"{VT_API_BASE}/files",
                    files=files,
                    timeout=60,  # uploads can be slow
                )

            # Rate limited
            if response.status_code == 429:
                logger.warning("VirusTotal rate limit hit during upload")
                return None

            if response.status_code in (401, 403):
                logger.error("VirusTotal API key is invalid or expired")
                return None

            response.raise_for_status()
            upload_data = response.json().get("data", {})
            analysis_id = upload_data.get("id")

            if not analysis_id:
                logger.warning("VirusTotal upload succeeded but no analysis ID returned")
                return None

            logger.info(f"File uploaded. Analysis ID: {analysis_id}. Polling for results...")

            # Poll for analysis completion
            return self._poll_analysis(analysis_id, file_path, poll_timeout)

        except requests.exceptions.Timeout:
            logger.warning("VirusTotal upload timed out")
            return None
        except requests.exceptions.ConnectionError:
            logger.warning("VirusTotal is unreachable (no network?)")
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"VirusTotal upload failed: {e}")
            return None
        except OSError as e:
            logger.warning(f"Cannot read file for upload: {e}")
            return None

    def _poll_analysis(
        self, analysis_id: str, file_path: str, timeout: int
    ) -> Optional[VirusTotalResult]:
        """Poll VT for analysis completion.

        Args:
            analysis_id: VT analysis ID from upload.
            file_path: Original file path (for result labeling).
            timeout: Max seconds to wait.

        Returns:
            VirusTotalResult when analysis is complete, or None on timeout.
        """
        url = f"{VT_API_BASE}/analyses/{analysis_id}"
        start_time = time.time()
        poll_interval = 10  # seconds between polls

        while (time.time() - start_time) < timeout:
            data = self._make_request(url)
            if data is None:
                time.sleep(poll_interval)
                continue

            attrs = data.get("attributes", {})
            status = attrs.get("status")

            if status == "completed":
                # Get the file hash from the analysis results
                meta = data.get("meta", {})
                file_info = meta.get("file_info", {})
                sha256 = file_info.get("sha256", "")

                if sha256:
                    # Fetch the full file report using the hash
                    return self.lookup_hash(sha256)
                else:
                    # Parse directly from analysis results
                    stats = attrs.get("stats", {})
                    malicious_count = stats.get("malicious", 0)
                    suspicious_count = stats.get("suspicious", 0)
                    total_engines = sum(stats.values()) if stats else 0
                    detection_count = malicious_count + suspicious_count

                    return VirusTotalResult(
                        hash_sha256=analysis_id,
                        detection_count=detection_count,
                        total_engines=total_engines,
                        malicious=detection_count > 0,
                        found=True,
                    )

            elif status == "queued" or status == "in-progress":
                elapsed = int(time.time() - start_time)
                logger.info(
                    f"VT analysis {status}... ({elapsed}s / {timeout}s timeout)"
                )
                time.sleep(poll_interval)
            else:
                logger.warning(f"Unexpected VT analysis status: {status}")
                time.sleep(poll_interval)

        logger.warning(f"VT analysis timed out after {timeout}s")
        return None

    # ── Internal helpers ──────────────────────────────────────────

    def _make_request(self, url: str) -> Optional[dict]:
        """Make an API request with retry on rate limit.

        Returns:
            Parsed JSON data dict, or None on error/not-found.
        """
        try:
            response = self._session.get(url, timeout=REQUEST_TIMEOUT)

            # Rate limited — wait and retry once
            if response.status_code == 429:
                logger.warning(
                    f"VirusTotal rate limit hit. Waiting {RATE_LIMIT_WAIT}s..."
                )
                time.sleep(RATE_LIMIT_WAIT)
                response = self._session.get(url, timeout=REQUEST_TIMEOUT)

                if response.status_code == 429:
                    logger.warning("VirusTotal rate limit persists. Skipping lookup.")
                    return None

            # Not found — hash/url/ip/domain not in VT database
            if response.status_code == 404:
                return None

            # Auth error
            if response.status_code in (401, 403):
                logger.error("VirusTotal API key is invalid or expired")
                return None

            response.raise_for_status()
            return response.json().get("data", {})

        except requests.exceptions.Timeout:
            logger.warning(f"VirusTotal request timed out for {url}")
            return None
        except requests.exceptions.ConnectionError:
            logger.warning("VirusTotal is unreachable (no network?)")
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"VirusTotal request failed: {e}")
            return None
        except (ValueError, KeyError) as e:
            logger.warning(f"VirusTotal response parse error: {e}")
            return None

    def _parse_file_response(
        self, file_hash: str, data: dict
    ) -> VirusTotalResult:
        """Parse a /files/ API response."""
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total_engines = sum(stats.values()) if stats else 0
        detection_count = malicious_count + suspicious_count

        # Extract detection names from individual engine results
        detection_names = []
        results = attrs.get("last_analysis_results", {})
        for engine_name, result in results.items():
            if result.get("category") in ("malicious", "suspicious"):
                engine_result = result.get("result")
                if engine_result:
                    detection_names.append(f"{engine_name}: {engine_result}")

        # Get the actual SHA-256 from the response (in case we looked up by MD5/SHA1)
        sha256 = attrs.get("sha256", file_hash)

        return VirusTotalResult(
            hash_sha256=sha256,
            detection_count=detection_count,
            total_engines=total_engines,
            detection_names=detection_names[:10],  # Keep top 10
            malicious=detection_count > 0,
            vt_link=f"https://www.virustotal.com/gui/file/{sha256}",
            found=True,
            scan_date=attrs.get("last_analysis_date"),
            tags=attrs.get("tags", []),
            suggested_threat_label=attrs.get(
                "popular_threat_classification", {}
            ).get("suggested_threat_label"),
        )

    def _parse_url_response(
        self, target_url: str, data: dict
    ) -> VirusTotalResult:
        """Parse a /urls/ API response."""
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total_engines = sum(stats.values()) if stats else 0
        detection_count = malicious_count + suspicious_count

        url_id = data.get("id", "")

        return VirusTotalResult(
            hash_sha256=url_id,
            detection_count=detection_count,
            total_engines=total_engines,
            malicious=detection_count > 0,
            vt_link=f"https://www.virustotal.com/gui/url/{url_id}",
            found=True,
            scan_date=attrs.get("last_analysis_date"),
            tags=attrs.get("tags", []),
        )

    def _parse_ip_response(
        self, ip_address: str, data: dict
    ) -> VirusTotalResult:
        """Parse an /ip_addresses/ API response."""
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total_engines = sum(stats.values()) if stats else 0
        detection_count = malicious_count + suspicious_count

        return VirusTotalResult(
            hash_sha256=ip_address,
            detection_count=detection_count,
            total_engines=total_engines,
            malicious=detection_count > 0,
            vt_link=f"https://www.virustotal.com/gui/ip-address/{ip_address}",
            found=True,
            tags=attrs.get("tags", []),
        )

    def _parse_domain_response(
        self, domain: str, data: dict
    ) -> VirusTotalResult:
        """Parse a /domains/ API response."""
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total_engines = sum(stats.values()) if stats else 0
        detection_count = malicious_count + suspicious_count

        return VirusTotalResult(
            hash_sha256=domain,
            detection_count=detection_count,
            total_engines=total_engines,
            malicious=detection_count > 0,
            vt_link=f"https://www.virustotal.com/gui/domain/{domain}",
            found=True,
            tags=attrs.get("tags", []),
        )
