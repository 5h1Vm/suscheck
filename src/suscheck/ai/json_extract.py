"""Extract JSON from LLM text (strip markdown fences)."""

from __future__ import annotations

import json
import re


def parse_json_response(text: str) -> dict:
    s = text.strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s, flags=re.I)
        s = re.sub(r"\s*```\s*$", "", s)
    return json.loads(s)
