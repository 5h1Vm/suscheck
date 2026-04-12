"""Clone wrapper for suscheck.

Handles git cloning safely after scanning.
"""

import subprocess
from typing import Optional

def clone_repo(url: str, dest: Optional[str] = None) -> int:
    """Execute git clone command."""
    cmd = ["git", "clone", url]
    if dest:
        cmd.append(dest)

    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode
    except FileNotFoundError:
        return 127
