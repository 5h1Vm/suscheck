from __future__ import annotations

import re
from pathlib import Path


MODULE_LITERAL_RE = re.compile(r"module\s*=\s*(?:f)?['\"]([^'\"]+)['\"]")
MODULE_ID_CONTRACT_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")


def test_module_identity_literals_follow_contract() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src_root = repo_root / "src" / "suscheck"

    violations: list[tuple[str, str]] = []
    for py_file in src_root.rglob("*.py"):
        text = py_file.read_text(encoding="utf-8", errors="ignore")
        for module_id in MODULE_LITERAL_RE.findall(text):
            if not MODULE_ID_CONTRACT_RE.match(module_id):
                rel_path = py_file.relative_to(repo_root)
                violations.append((str(rel_path), module_id))

    assert violations == []
