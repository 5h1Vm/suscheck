"""Recursive Decoder Engine.

Iteratively unwraps obfuscated payloads up to a maximum depth,
returning all exposed cleartext layers so they can be scanned
by the core detection engines.
"""

import logging

from suscheck.modules.detectors.encoded_strings import detect_encoded_strings

logger = logging.getLogger(__name__)

MAX_DECODE_DEPTH = 10


class RecursiveDecoderEngine:
    """Iterative un-wrapper for malicious encoded payloads."""

    def __init__(self, max_depth: int = MAX_DECODE_DEPTH):
        self.max_depth = max_depth

    def extract_deep_payloads(self, content: str, file_path: str = "") -> str:
        """Scan content for encoded payloads and iteratively decode them.

        Args:
            content: Raw text content to scan.
            file_path: Optional context path for logging.

        Returns:
            A string containing all deep payloads found, formatted with
            pseudo-headers to separate them from original code.
            Returns empty string if no obfuscation layers are found.
        """
        extracted_layers = []
        seen_payloads = set()

        # We loop through newly discovered payloads
        current_layer_payloads = [content]

        for depth in range(1, self.max_depth + 1):
            next_layer_payloads = []

            for payload in current_layer_payloads:
                findings = detect_encoded_strings(payload, file_path)

                for f in findings:
                    full_decoded = f.evidence.get("full_decoded")
                    
                    if full_decoded and full_decoded not in seen_payloads:
                        seen_payloads.add(full_decoded)
                        
                        # Add header to demarcate depth trace
                        layer_header = (
                            f"\n\n--- SUSCHECK DEEP DECODED PAYLOAD "
                            f"(Depth: {depth}, Encoding: {f.evidence.get('encoding')}) "
                            f"---\n"
                        )
                        combined = layer_header + full_decoded
                        extracted_layers.append(combined)
                        
                        # Send this specific decoded text down to next iteration loop
                        next_layer_payloads.append(full_decoded)

            if not next_layer_payloads:
                break  # Bottomed out: No deeper encodings found

            current_layer_payloads = next_layer_payloads

        if extracted_layers:
            logger.debug(
                f"Recursively peeled {len(extracted_layers)} encoded "
                f"layer(s) from {file_path}"
            )

        return "".join(extracted_layers)
