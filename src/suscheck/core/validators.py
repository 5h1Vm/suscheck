"""Production-ready validation utilities for reliability and safety."""

import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Raised when validation fails with actionable message."""
    pass


def validate_file_exists(file_path: str | Path, context: str = "File") -> Path:
    """Validate file exists and return Path object.
    
    Args:
        file_path: Path to validate
        context: Context for error message (e.g., "Config file", "Input file")
        
    Returns:
        Path object if valid
        
    Raises:
        ValidationError: If file doesn't exist with clear message
    """
    path = Path(file_path)
    if not path.exists():
        raise ValidationError(f"{context} not found: {file_path}")
    if not path.is_file():
        raise ValidationError(f"{context} is not a file: {file_path}")
    return path


def validate_directory_exists(dir_path: str | Path, context: str = "Directory") -> Path:
    """Validate directory exists and return Path object.
    
    Args:
        dir_path: Path to validate
        context: Context for error message
        
    Returns:
        Path object if valid
        
    Raises:
        ValidationError: If directory doesn't exist
    """
    path = Path(dir_path)
    if not path.exists():
        raise ValidationError(f"{context} not found: {dir_path}")
    if not path.is_dir():
        raise ValidationError(f"{context} is not a directory: {dir_path}")
    return path


def validate_tool_available(tool_name: str, context: str = "") -> str:
    """Validate that a tool/executable is available in $PATH.
    
    Args:
        tool_name: Name of the tool to check (e.g., "git", "pip", "npm")
        context: Additional context for error message
        
    Returns:
        Full path to the tool if available
        
    Raises:
        ValidationError: If tool not found with clear remediation
    """
    path = shutil.which(tool_name)
    if not path:
        msg = f"Required tool not found in $PATH: {tool_name}"
        if context:
            msg += f"\n  Context: {context}"
        msg += f"\n  Install it from: https://www.{tool_name}.com or your package manager"
        raise ValidationError(msg)
    logger.debug(f"Tool '{tool_name}' found at: {path}")
    return path


def validate_config_int(value: any, key: str, default: int, min_val: int = 0) -> int:
    """Safely convert config value to int with validation.
    
    Args:
        value: Value from config (may be str, int, dict, etc.)
        key: Config key name (for error messages)
        default: Default value if missing
        min_val: Minimum allowed value
        
    Returns:
        Valid int value
        
    Raises:
        ValidationError: If value can't be converted or is invalid
    """
    if value is None:
        return default
    
    # Try to convert
    try:
        int_val = int(value)
    except (ValueError, TypeError):
        raise ValidationError(
            f"Config key '{key}' must be an integer, got {type(value).__name__}: {value}"
        )
    
    # Validate range
    if int_val < min_val:
        raise ValidationError(
            f"Config key '{key}' must be >= {min_val}, got {int_val}"
        )
    
    return int_val


def validate_json_safety(file_path: str | Path) -> dict:
    """Safely load and validate JSON file.
    
    Args:
        file_path: Path to JSON file
        
    Returns:
        Parsed JSON object
        
    Raises:
        ValidationError: If file is invalid JSON
    """
    import json
    
    path = validate_file_exists(file_path, context="JSON file")
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValidationError(
            f"Invalid JSON in {file_path}:\n  Line {e.lineno}, Col {e.colno}: {e.msg}"
        )
    except OSError as e:
        raise ValidationError(f"Cannot read JSON file {file_path}: {e}")
    
    return data


def validate_command_available(cmd: list[str], context: str = "") -> None:
    """Validate that a command can be executed (check first element exists).
    
    Args:
        cmd: Command list (e.g., ["semgrep", "scan", "file.py"])
        context: Additional context
        
    Raises:
        ValidationError: If command executable not found
    """
    if not cmd:
        raise ValidationError("Empty command list")
    
    tool = cmd[0]
    try:
        validate_tool_available(tool, context=context or f"Running: {' '.join(cmd[:2])}")
    except ValidationError:
        raise


def safe_file_size(file_path: str | Path) -> int:
    """Get file size safely, handling race conditions.
    
    Args:
        file_path: Path to file
        
    Returns:
        File size in bytes
        
    Raises:
        ValidationError: If file doesn't exist or can't be stat'd
    """
    path = Path(file_path)
    try:
        return path.stat().st_size
    except FileNotFoundError:
        raise ValidationError(f"File not found (may have been deleted): {file_path}")
    except OSError as e:
        raise ValidationError(f"Cannot access file: {file_path}\n  Error: {e}")


def should_skip_large_file(file_path: str | Path, max_bytes: int) -> bool:
    """Check if file should be skipped due to size.
    
    Args:
        file_path: Path to file
        max_bytes: Maximum allowed size a
        
    Returns:
        True if file exceeds max_bytes and should be skipped
    """
    try:
        size = safe_file_size(file_path)
        return size > max_bytes
    except ValidationError as e:
        logger.warning(f"Cannot determine file size for {file_path}: {e}")
        return False  # Don't skip if we can't determine size


__all__ = [
    "ValidationError",
    "validate_file_exists",
    "validate_directory_exists",
    "validate_tool_available",
    "validate_config_int",
    "validate_json_safety",
    "validate_command_available",
    "safe_file_size",
    "should_skip_large_file",
]
