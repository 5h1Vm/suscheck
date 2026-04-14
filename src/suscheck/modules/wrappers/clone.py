"""Clone wrapper for suscheck.

Handles git cloning safely after scanning.
"""

import logging
import subprocess
from typing import Optional

from suscheck.core.validators import validate_tool_available, ValidationError

logger = logging.getLogger(__name__)


def clone_repo(url: str, dest: Optional[str] = None) -> int:
    """Execute git clone command.
    
    Args:
        url: Git repository URL
        dest: Optional destination directory
        
    Returns:
        Exit code (0 = success, non-zero = failure)
    """
    # ✅ Pre-validate git exists before attempting clone
    try:
        validate_tool_available("git", context="Running git clone")
    except ValidationError as e:
        logger.error(f"Clone failed: {e}")
        return 127
    
    cmd = ["git", "clone", url]
    if dest:
        cmd.append(dest)
    
    logger.info(f"Cloning repository: {url}")
    
    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode
    except FileNotFoundError as e:
        logger.error(f"Failed to execute git: {e}")
        return 127
    except Exception as e:
        logger.error(f"Clone failed with unexpected error: {e}", exc_info=True)
        return 1
