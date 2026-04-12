"""PyPI JSON API Client for mapping package metadata."""

import datetime
import logging
from dataclasses import dataclass
from typing import Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class PyPIMetadata:
    """Core trust metadata extracted from PyPI."""
    name: str
    version: str
    author: str
    author_email: str
    maintainer: str
    home_page: str
    project_urls: dict
    yanked: bool
    upload_time: Optional[datetime.datetime]
    latest_version: str = ""
    latest_upload_time: Optional[datetime.datetime] = None
    size: int = 0


class PyPIClient:
    """Client for querying PyPI for package signals."""

    BASE_URL = "https://pypi.org/pypi"

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SusCheck/0.1.0 (Security Scanner)",
        })

    def get_package_metadata(self, package_name: str, version: Optional[str] = None) -> Optional[PyPIMetadata]:
        """Fetch and parse metadata for a package, capturing both specific and latest version info."""
        # We always start with the base URL to get the global 'latest' information
        url = f"{self.BASE_URL}/{package_name}/json"
        
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                logger.debug(f"PyPI API returned {resp.status_code} for {package_name}")
                return None

            data = resp.json()
            info = data.get("info", {})
            releases = data.get("releases", {})
            
            latest_version = info.get("version", "")
            
            # If a specific version was requested, we need to extract its metadata
            # otherwise we use the 'info' which is already 'latest'.
            target_version = version if version else latest_version
            
            # Extract metadata for the target version
            # Note: PyPI info dictionary in the base JSON reflects the LATEST version.
            # If we want metadata for an OLDER version, we have to be careful.
            
            # If target_version == latest_version, we can use 'info'.
            # Otherwise, we might need a separate call OR parse releases.
            
            target_info = info
            if version and version != latest_version:
                # To get accurate 'yanked' etc for an old version, we SHOULD hit the version-specific URL
                # as the root JSON 'info' is for latest.
                v_url = f"{self.BASE_URL}/{package_name}/{version}/json"
                v_resp = self.session.get(v_url, timeout=self.timeout)
                if v_resp.status_code == 200:
                    target_info = v_resp.json().get("info", {})

            # Get upload times
            def get_upload_time(v_name):
                v_releases = releases.get(v_name, [])
                if v_releases:
                    time_str = v_releases[0].get("upload_time")
                    if time_str:
                        return datetime.datetime.fromisoformat(time_str)
                return None

            upload_time = get_upload_time(target_version)
            latest_upload_time = get_upload_time(latest_version)

            return PyPIMetadata(
                name=info.get("name", package_name),
                version=target_version,
                author=target_info.get("author", ""),
                author_email=target_info.get("author_email", ""),
                maintainer=target_info.get("maintainer", ""),
                home_page=target_info.get("home_page", ""),
                project_urls=target_info.get("project_urls") or {},
                yanked=target_info.get("yanked", False),
                upload_time=upload_time,
                latest_version=latest_version,
                latest_upload_time=latest_upload_time,
                size=releases.get(target_version, [{}])[0].get("size", 0)
            )
        except Exception as e:
            logger.debug(f"PyPI fetch failed: {e}")
            return None
