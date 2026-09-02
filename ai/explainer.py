"""
ai/explainer.py
===============
Attack trace → Plain English explanation for QuantumScyther AI.

STATUS: Phase 3 — NOT YET IMPLEMENTED
This file defines the interface and documents the planned design.

Purpose
-------
Takes a VerificationResult (from the engine) and generates:
  1. A plain-English paragraph explaining what happened and why
  2. A concrete fix suggestion for the protocol

CRITICAL RULE: Grounded output only
-------------------------------------
The explanation is derived FROM the engine's attack trace.
The LLM is NOT asked to independently reason about security.
The prompt includes the full trace and the LLM only generates
natural language — it does not infer new facts.

This prevents hallucination: if the engine says MITM, the
explanation says MITM. The LLM cannot disagree with the engine.

Example input (VerificationResult.trace):
    ["Session 0 (I) sends: {Na,A}Kb",
     "Session 1 (R) sends: {Na,Nb}Ka",
     "Responder session 1 completed — no matching initiator run"]

Example output:
    "The attacker intercepted Alice's first message and forwarded it
     to Bob while impersonating Alice. When Bob responded, the attacker
     relayed the response back to Alice. As a result, Bob believes he
     completed a session with Alice, but Alice was actually talking to
     the attacker throughout.
     Fix: Add Bob's identity to Message 2: {Na, Nb, B}Ka. This allows
     Alice to verify that the responder is indeed Bob."
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional


# ── Interface (to be implemented in Phase 3) ──────────────────────────────────

class Explainer:
    """
    Converts an engine attack trace into plain English
    and suggests a protocol fix.

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
        return self._available

    def explain(
        self,
        attack_type:  str,
        trace:        List[str],
        protocol_name: str = "",
        primitives:   List[str] = None,
    ) -> Dict[str, str]:
        """
        Generate a plain-English explanation of an attack.

        Parameters
        ----------
        attack_type   : str — e.g. "MITM", "Replay"
        trace         : list of str — engine attack trace lines
        protocol_name : str — e.g. "NSPK"
        primitives    : list of str — cryptographic primitives in the protocol

        Returns
        -------
        dict with keys:
            "explanation" : str — plain English paragraph
            "fix"         : str — concrete fix suggestion

        Raises
        ------
        NotImplementedError — Phase 3 not yet built
        RuntimeError        — if no API key available
        """
        raise NotImplementedError(
            "Explainer.explain() will be implemented in Phase 3. "
            "The engine's attack trace is the ground truth — the LLM "
            "will only translate it into English."
        )

    def status(self) -> str:
        if self._available:
            return f"Explainer: {self.provider} API key configured — ready for Phase 3"
        return "Explainer: No API key — plain trace output only (Phase 3 pending)"

    def fallback_explanation(
        self,
        attack_type: str,
        trace: List[str],
    ) -> Dict[str, str]:
        """
        No-LLM fallback: returns the engine trace formatted as plain text.
        Used when no API key is available.
        """
        trace_text = "\n".join(f"  {line}" for line in trace)
        return {
            "explanation": (
                f"Attack type: {attack_type}\n"
                f"Engine trace:\n{trace_text}\n"
                f"(Plain-English explanation requires LLM API key — Phase 3)"
            ),
            "fix": "Fix suggestion requires LLM API key — Phase 3 pending.",
        }


if __name__ == "__main__":
    exp = Explainer()
    print(exp.status())
    print("Phase 3 implementation pending.")
    # Fallback works without API key:
    result = exp.fallback_explanation(
        attack_type="MITM",
        trace=[
            "Session 0 (I) sends: {Na,A}Ke",
            "Session 1 (R) receives: {Na,A}Kb",
            "Session 1 (R) sends: {Na,Nb}Ka",
            "Session 0 (I) receives: {Na,Nb}Ka",
            "Authentication violation: responder has no matching initiator run",
        ],
    )
    print("\nFallback output:")
    print(result["explanation"])
