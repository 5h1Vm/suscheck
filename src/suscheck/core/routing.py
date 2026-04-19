"""Shared scan routing helpers.

Centralizes route and module-dispatch decisions so command orchestration
and pipeline traversal remain behaviorally consistent.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from suscheck.core.auto_detector import ArtifactType, DetectionResult


class ScanRoute(str, Enum):
    DIRECTORY = "directory"
    LOCAL_FILE = "local_file"
    REMOTE_REPOSITORY = "remote_repository"
    PACKAGE_OR_OTHER = "package_or_other"


def resolve_scan_route(*, target: str, target_path: Path, detection: DetectionResult) -> ScanRoute:
    """Resolve the canonical scan route for a target."""
    if target_path.is_dir():
        return ScanRoute.DIRECTORY
    if target_path.is_file():
        return ScanRoute.LOCAL_FILE
    if detection.artifact_type == ArtifactType.REPOSITORY and target.startswith(("http://", "https://", "git@")):
        return ScanRoute.REMOTE_REPOSITORY
    return ScanRoute.PACKAGE_OR_OTHER


def should_run_code_scan(detection: DetectionResult) -> bool:
    """Return whether code-oriented scanning should be used for this artifact."""
    return detection.artifact_type in (ArtifactType.CODE, ArtifactType.UNKNOWN) or detection.type_mismatch


def infer_primary_static_module(detection: DetectionResult) -> str | None:
    """Infer the primary static module bucket from detection result."""
    if should_run_code_scan(detection):
        return "code"
    if detection.artifact_type == ArtifactType.CONFIG:
        return "config"
    if detection.artifact_type == ArtifactType.MCP_SERVER:
        return "mcp"
    return None
