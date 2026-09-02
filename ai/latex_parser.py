"""
ai/latex_parser.py
==================
LaTeX → Protocol AST parser for QuantumScyther AI.

STATUS: Phase 3 — NOT YET IMPLEMENTED
This file defines the interface and documents the planned design.
Implementation begins in Phase 3.

Purpose
-------
Accepts cryptographic protocol notation as written in research papers
(LaTeX or arrow notation) and converts it into a structured Protocol AST
(dict matching annotation_schema.ProtocolRecord fields).

Method: few-shot prompting with GPT-4o / Claude.
LaTeX notation is ambiguous and varies by author — an LLM handles
this better than a rigid regex parser.

Fallback
--------
If no LLM API key is available, the system accepts manual YAML input.
The YAML schema matches annotation_schema.ProtocolRecord fields exactly.

Example input (LaTeX):
    \\text{A} \\rightarrow \\text{B} : \\{N_a, A\\}_{K_b}
    \\text{B} \\rightarrow \\text{A} : \\{N_a, N_b\\}_{K_a}
    \\text{A} \\rightarrow \\text{B} : \\{N_b\\}_{K_b}

Example output (Protocol AST dict):
    {
        "protocol_name": "NSPK",
        "participants": ["A", "B"],
        "messages": [
            {"step": 1, "sender": "A", "receiver": "B",
             "message": "{Na,A}Kb", "protection": "public_key_encryption"},
            ...
        ],
        "cryptographic_primitives": ["Public_Key_Encryption", "Nonce"]
    }
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional


# ── Interface (to be implemented in Phase 3) ──────────────────────────────────

class LaTeXParser:
    """
    Parses LaTeX or arrow-notation protocol specifications into
    a structured Protocol AST using few-shot LLM prompting.

    Parameters
    ----------
    provider : str — "openai" | "anthropic" | "none"
    api_key  : str — API key (reads from env if not provided)
    """

    def __init__(
        self,
        provider: str = "openai",
        api_key:  Optional[str] = None,
    ) -> None:
        self.provider = provider
        self.api_key  = api_key or os.environ.get("OPENAI_API_KEY") or \
                        os.environ.get("ANTHROPIC_API_KEY")
        self._available = bool(self.api_key) and provider != "none"

    @property
    def available(self) -> bool:
        """True if an LLM API key is configured."""
        return self._available

    def parse(self, latex_text: str) -> Dict[str, Any]:
        """
        Parse LaTeX protocol notation into a Protocol AST dict.

        Parameters
        ----------
        latex_text : str — raw LaTeX or arrow-notation text

        Returns
        -------
        dict — Protocol AST compatible with annotation_schema.ProtocolRecord

        Raises
        ------
        NotImplementedError — Phase 3 not yet built
        RuntimeError       — if no API key and no YAML fallback provided
        """
        raise NotImplementedError(
            "LaTeXParser.parse() will be implemented in Phase 3. "
            "Use the YAML fallback (parse_yaml()) or the interactive "
            "CLI (analyze.py) in the meantime."
        )

    def parse_yaml(self, yaml_text: str) -> Dict[str, Any]:
        """
        Parse a YAML protocol specification as a fallback when no LLM is available.

        Parameters
        ----------
        yaml_text : str — YAML string matching ProtocolRecord fields

        Returns
        -------
        dict — Protocol AST

        Raises
        ------
        NotImplementedError — Phase 3 not yet built
        """
        raise NotImplementedError(
            "LaTeXParser.parse_yaml() will be implemented in Phase 3."
        )

    def status(self) -> str:
        """Return a human-readable status string."""
        if self._available:
            return f"LaTeXParser: {self.provider} API key configured — ready for Phase 3"
        return "LaTeXParser: No API key — YAML fallback only (Phase 3 pending)"


# ── Placeholder for Phase 3 ───────────────────────────────────────────────────

def parse_protocol(text: str, provider: str = "openai") -> Dict[str, Any]:
    """
    Module-level convenience function.
    Will be implemented in Phase 3.
    """
    parser = LaTeXParser(provider=provider)
    return parser.parse(text)


if __name__ == "__main__":
    parser = LaTeXParser()
    print(parser.status())
    print("Phase 3 implementation pending.")
