"""Connect wrapper for suscheck.

Handles MCP server connection safety checks.
"""

from typing import Dict, Any

def connect_mcp(target: str, pri_score: float, force: bool = False) -> Dict[str, Any]:
    """Verify if an MCP target is safe to connect.
    
    This wrapper doesn't perform the connection but validates the 
    security state for the CLI to display.
    """
    is_safe = pri_score <= 15
    can_proceed = is_safe or force
    
    return {
        "target": target,
        "is_safe": is_safe,
        "can_proceed": can_proceed,
        "pri_score": pri_score
    }
