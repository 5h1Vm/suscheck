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
    size: int


class PyPIClient:
    """Client for querying PyPI for package signals."""

    BASE_URL = "https://pypi.org/pypi"

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SusCheck/0.1.0 (Security Scanner)",
        })

    def get_package_metadata(self, package_name: str) -> Optional[PyPIMetadata]:
        """Fetch and parse metadata for a specific package."""
        url = f"{self.BASE_URL}/{package_name}/json"
        
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                logger.debug(f"PyPI API returned {resp.status_code} for {package_name}")
                return None

            data = resp.json()
            info = data.get("info", {})
            releases = data.get("releases", {})
            current_version = info.get("version", "")
            
            # Find upload time of current version safely
            upload_time = None
            size = 0
            if current_version in releases and releases[current_version]:
                # Grab first distribution upload (usually sdist or wheel)
                dist_info = releases[current_version][0]
                time_str = dist_info.get("upload_time")
                if time_str:
                    upload_time = datetime.datetime.fromisoformat(time_str)
                size = dist_info.get("size", 0)

            return PyPIMetadata(
                name=info.get("name", package_name),
                version=current_version,
                author=info.get("author", ""),
                author_email=info.get("author_email", ""),
                maintainer=info.get("maintainer", ""),
                home_page=info.get("home_page", ""),
                project_urls=info.get("project_urls") or {},
                yanked=info.get("yanked", False),
                upload_time=upload_time,
                size=size
            )
        except Exception as e:
            logger.debug(f"PyPI fetch failed: {e}")
            return None
