#!/usr/bin/env python3
"""A normal, benign Python script for testing false positive resistance.

This should produce ZERO security findings from the code scanner.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path


def load_config(config_path: str) -> dict:
    """Load configuration from a JSON file."""
    path = Path(config_path)
    if not path.exists():
        return {"debug": False, "log_level": "INFO"}

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def process_data(items: list[str]) -> list[str]:
    """Process a list of strings."""
    results = []
    for item in items:
        cleaned = item.strip().lower()
        if cleaned:
            results.append(cleaned)
    return results


def calculate_stats(numbers: list[float]) -> dict:
    """Calculate basic statistics."""
    if not numbers:
        return {"count": 0, "mean": 0.0, "total": 0.0}

    total = sum(numbers)
    mean = total / len(numbers)
    return {
        "count": len(numbers),
        "mean": round(mean, 2),
        "total": round(total, 2),
        "min": min(numbers),
        "max": max(numbers),
    }


class DataProcessor:
    """Processes data files."""

    def __init__(self, input_dir: str, output_dir: str):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> int:
        """Process all files and return count."""
        count = 0
        for file_path in self.input_dir.glob("*.txt"):
            with open(file_path, "r") as f:
                data = f.read()
            processed = process_data(data.splitlines())
            output_path = self.output_dir / file_path.name
            with open(output_path, "w") as f:
                f.write("\n".join(processed))
            count += 1
        return count


def main():
    """Main entry point."""
    config = load_config("config.json")
    print(f"Starting at {datetime.now().isoformat()}")
    print(f"Python {sys.version}")
    print(f"Debug: {config.get('debug', False)}")

    processor = DataProcessor("input", "output")
    count = processor.run()
    print(f"Processed {count} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
