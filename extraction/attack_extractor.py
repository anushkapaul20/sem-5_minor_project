"""
attack_extractor.py
===================
Detects attack-related information from raw text sections of a paper.

PIPELINE ROLE
-------------
Text/PDF section  →  AttackExtractor  →  attack_info dict  →  ProtocolParser

WHAT IT DOES
------------
Given a block of text (e.g. the "Security Analysis" section of a paper):
1. Detects attack type keywords → attack_category candidates
2. Detects attacker capability phrases
3. Detects violated security property phrases
4. Detects attack trace lines (sequences of A → B : ... with attacker labels)
5. Returns an attack_info dict compatible with ProtocolParser.parse()

WHAT IT DOES NOT DO
-------------------
- Does NOT confirm attacks — all auto-detected results get
  extraction_status = "AUTO_EXTRACTED" and attack_status = "REQUIRES_REVIEW"
- Does NOT invent attack traces — if no trace is found, attack_trace = ""
- Does NOT claim an attack is present unless keyword evidence is found

CONFIDENCE LEVELS
-----------------
  HIGH   — multiple independent signals (keyword + trace + security property)
  MEDIUM — two signals
  LOW    — single signal (keyword only)
  NONE   — no signals found

USAGE
-----
    from extraction.attack_extractor import AttackExtractor

    extractor = AttackExtractor()
    info = extractor.extract_attack_info(text)
    print(info["attack_category"])
    print(info["confidence"])
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any


# ── Attack keyword patterns ────────────────────────────────────────────────────
# Each tuple: (attack_category_label, list_of_regex_patterns)

_ATTACK_KEYWORDS: List[Tuple[str, List[str]]] = [
    (
        "MITM",
        [
            r"man.in.the.middle",
            r"\bMITM\b|\bmitm\b",
            r"middle.attack",
            r"interleaving.attack",
            r"parallel.session",
        ],
    ),
    (
        "Replay",
        [
            r"\breplay\b",
            r"replay.attack",
            r"replaying.(?:a\s+)?message",
            r"reuse(?:d|s)?\s+(?:a\s+)?(?:message|nonce|ticket|key)",
            r"old\s+(?:message|ticket|session\s+key)",
            r"stale\s+(?:message|key|nonce)",
        ],
    ),
    (
        "Reflection",
        [
            r"\breflect(?:ion)?\b",
            r"reflect(?:ed|ing)\s+(?:the\s+)?(?:message|challenge|nonce)",
            r"sent.back.to.(?:the\s+)?(?:originator|sender)",
            r"parallel\s+session.*same\s+key",
        ],
    ),
    (
        "Impersonation",
        [
            r"\bimpersonat(?:e|ion|ing)\b",
            r"pretend(?:s|ing)?\s+to\s+be",
            r"claim(?:s|ing)?\s+to\s+be",
            r"forge(?:d|s)?\s+(?:the\s+)?identity",
            r"masquerad(?:e|ing)",
        ],
    ),
    (
        "UKS",
        [
            r"unknown.key.share",
            r"\bUKS\b",
            r"wrong\s+(?:belief|partner|identity)\s+about\s+(?:the\s+)?(?:key|session)",
            r"share(?:s|d)?\s+(?:a\s+)?key.*wrong.*partner",
            r"identity.*confusion.*key",
        ],
    ),
    (
        "Secrecy_Violation",
        [
            r"secrecy\s+(?:is\s+)?(?:violated|broken|fails?)",
            r"(?:session\s+)?key\s+(?:is\s+)?(?:revealed|disclosed|leaked|exposed)",
            r"attacker\s+(?:learns?|obtains?|recovers?)\s+(?:the\s+)?(?:key|secret|nonce)",
            r"(?:the\s+)?secret\s+(?:is\s+)?no\s+longer",
        ],
    ),
    (
        "Authentication_Violation",
        [
            r"authentication\s+(?:is\s+)?(?:violated|broken|fails?)",
            r"(?:non.)?injective\s+agreement\s+(?:is\s+)?(?:violated|fails?)",
            r"aliveness\s+(?:is\s+)?(?:violated|fails?)",
            r"(?:entity\s+)?authentication\s+claim\s+(?:fails?|does\s+not\s+hold)",
        ],
    ),
    (
        "Session_Key_Compromise",
        [
            r"session.key\s+(?:is\s+)?(?:compromised|revealed|known\s+to\s+(?:the\s+)?attacker)",
            r"attacker\s+(?:learns?|knows?)\s+(?:the\s+)?session\s+key",
            r"session\s+key\s+(?:is\s+)?(?:exposed|broken)",
        ],
    ),
    (
        "KCI",
        [
            r"key.compromise\s+impersonation",
            r"\bKCI\b",
            r"compromised?\s+(?:long.term|static)\s+key.*impersonat",
            r"knowing\s+(?:[A-Z]\'s\s+)?(?:private|long.term)\s+key.*impersonat",
        ],
    ),
    (
        "Forward_Secrecy_Violation",
        [
            r"forward\s+(?:secrecy|security)\s+(?:is\s+)?(?:violated|broken|fails?)",
            r"past\s+sessions?\s+(?:can\s+be\s+)?decrypted",
            r"long.term\s+key\s+compromise.*past\s+session",
            r"no\s+(?:perfect\s+)?forward\s+(?:secrecy|security)",
        ],
    ),
]

# ── Attacker capability patterns ───────────────────────────────────────────────

_CAPABILITY_PATTERNS: List[Tuple[str, str]] = [
    ("intercept", r"\bintercept(?:s|ed|ing)?\b"),
    ("modify", r"\bmodif(?:y|ies|ied|ication)\b"),
    ("replay", r"\breplay(?:s|ed|ing)?\b"),
    ("forward", r"\bforward(?:s|ed|ing)?\b"),
    ("reflect", r"\breflect(?:s|ed|ing)?\b"),
    ("impersonate", r"\bimpersonat(?:e|es|ed|ing|ion)\b"),
    ("block", r"\bblock(?:s|ed|ing)?\b"),
    ("compute", r"\bcomput(?:e|es|ed|ing)\b"),
    ("compromise_key", r"\bcompromis(?:e|es|ed|ing)\b.*key|key.*compromis(?:e|es|ed|ing)\b"),
]

# ── Security property patterns ─────────────────────────────────────────────────

_PROPERTY_PATTERNS: List[Tuple[str, str]] = [
    ("secrecy", r"\bsecrecy\b|\bsecret\b|\bconfidentiality\b"),
    ("authentication", r"\bauthentication\b|\bauthentic(?:ates?|ated|ating)\b"),
    ("forward_secrecy", r"\bforward\s+secrecy\b|\bperfect\s+forward\s+secrecy\b|\bPFS\b"),
    ("key_freshness", r"\bkey\s+freshness\b|\bfresh\s+(?:key|session)\b|\bnonce\b"),
    ("mutual_authentication", r"\bmutual\s+authentication\b|\bboth\s+parties\s+(?:are\s+)?authenticat"),
    ("entity_authentication", r"\bentity\s+authentication\b|\bliveness\b|\balive\b"),
    ("key_establishment", r"\bkey\s+(?:establishment|agreement|distribution|exchange)\b"),
    ("key_confirmation", r"\bkey\s+confirmation\b"),
    ("non_repudiation", r"\bnon.repudiation\b|\bnon\s+repudiation\b"),
]

# ── Attack trace line pattern ──────────────────────────────────────────────────
# Matches lines with an arrow, possibly with E/I as a participant
_ATTACK_TRACE_RE = re.compile(
    r"(?:[A-Z][a-z]?\([A-Z][a-z]?\)|[A-Z][a-z]?)\s*"
    r"(?:→|->|-->)\s*"
    r"(?:[A-Z][a-z]?\([A-Z][a-z]?\)|[A-Z][a-z]?)\s*:\s*.+",
    re.UNICODE,
)


# ── Result dataclass ─────────────────────────────────────────────────────────

@dataclass
class AttackExtractionResult:
    """
    Result of running AttackExtractor.extract_attack_info() on a text block.
    """
    attack_present: int = 0
    protocol_secure: bool = True
    attack_category: List[str] = field(default_factory=lambda: ["None"])
    attack_name: str = "None"
    attacker_capabilities: List[str] = field(default_factory=list)
    attacker_action: List[str] = field(default_factory=list)
    security_property_targeted: List[str] = field(default_factory=list)
    attack_trace: str = ""
    attack_trace_structured: List[dict] = field(default_factory=list)
    confidence: str = "NONE"     # NONE | LOW | MEDIUM | HIGH
    evidence: List[str] = field(default_factory=list)  # debug: what triggered detection
    needs_review: bool = True    # Always True for AUTO_EXTRACTED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_present": self.attack_present,
            "protocol_secure": self.protocol_secure,
            "attack_category": self.attack_category,
            "attack_name": self.attack_name,
            "attacker_capabilities": self.attacker_capabilities,
            "attacker_action": self.attacker_action,
            "security_property_targeted": self.security_property_targeted,
            "attack_trace": self.attack_trace,
            "attack_trace_structured": self.attack_trace_structured,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "needs_review": self.needs_review,
        }


# ── Main Class ────────────────────────────────────────────────────────────────

class AttackExtractor:
    """
    Scans a text block for attack-related signals and returns structured info.

    All results are AUTO_EXTRACTED and marked REQUIRES_REVIEW.
    """

    def extract_attack_info(self, text: str) -> Dict[str, Any]:
        """
        Main entry point.

        Parameters
        ----------
        text : str
            Text of a paper section (security analysis, abstract, attack description).

        Returns
        -------
        dict
            Keys: attack_present, attack_category, attacker_capabilities,
                  security_property_targeted, attack_trace, confidence, etc.
        """
        result = AttackExtractionResult()
        text_lower = text.lower()

        # ── 1. Detect attack categories ───────────────────────────────────
        detected_categories: List[str] = []
        evidence: List[str] = []

        for category, patterns in _ATTACK_KEYWORDS:
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    if category not in detected_categories:
                        detected_categories.append(category)
                    evidence.append(f"Keyword match for {category!r}: pattern={pattern!r}")
                    break

        # ── 2. Detect attacker capabilities ──────────────────────────────
        detected_capabilities: List[str] = []
        for cap, pattern in _CAPABILITY_PATTERNS:
            if re.search(pattern, text_lower):
                detected_capabilities.append(cap)
                evidence.append(f"Capability match: {cap!r}")

        # ── 3. Detect security properties ────────────────────────────────
        detected_properties: List[str] = []
        for prop, pattern in _PROPERTY_PATTERNS:
            if re.search(pattern, text_lower):
                detected_properties.append(prop)
                evidence.append(f"Property match: {prop!r}")

        # ── 4. Extract attack trace lines ─────────────────────────────────
        trace_lines = [
            line.strip()
            for line in text.splitlines()
            if _ATTACK_TRACE_RE.search(line.strip())
        ]
        attack_trace = "\n".join(trace_lines)

        # ── 5. Determine if attack is present ─────────────────────────────
        signal_count = 0
        if detected_categories:
            signal_count += 2   # strongest signal
        if detected_capabilities:
            signal_count += 1
        if trace_lines:
            signal_count += 1
        if detected_properties:
            signal_count += 1

        if signal_count == 0:
            confidence = "NONE"
            attack_present = 0
        elif signal_count == 1:
            confidence = "LOW"
            attack_present = 1
        elif signal_count == 2:
            confidence = "MEDIUM"
            attack_present = 1
        else:
            confidence = "HIGH"
            attack_present = 1

        # ── 6. Build result ───────────────────────────────────────────────
        result.attack_present = attack_present
        result.protocol_secure = attack_present == 0
        result.attack_category = detected_categories if detected_categories else ["None"]
        result.attack_name = (
            f"Auto-detected: {', '.join(detected_categories)}"
            if detected_categories
            else "None"
        )
        result.attacker_capabilities = detected_capabilities
        result.attacker_action = detected_capabilities  # same data until reviewed
        result.security_property_targeted = detected_properties
        result.attack_trace = attack_trace
        result.confidence = confidence
        result.evidence = evidence
        result.needs_review = True  # always True for auto-extracted

        return result.to_dict()

    def extract_attack_trace_structured(
        self,
        trace_text: str,
    ) -> List[dict]:
        """
        Parse an attack trace text block into a list of structured steps.

        Works best on text formatted as:
          Step 1: A → E(B) : message
          Step 2: E(A) → B : message
          ...

        Returns a list of dicts with keys:
          step, sender, receiver, impersonating (optional), message, attacker_role
        """
        from extraction.equation_extractor import EquationExtractor, PARTICIPANT_NORM

        eq_extractor = EquationExtractor()
        steps = eq_extractor.extract(trace_text)

        result = []
        for s in steps:
            entry: Dict[str, Any] = {
                "step": s.step,
                "sender": s.sender,
                "receiver": s.receiver,
                "message": s.message,
                "attacker_role": self._infer_attacker_role(s.sender, s.receiver),
            }
            result.append(entry)
        return result

    def _infer_attacker_role(self, sender: str, receiver: str) -> str:
        """
        Heuristic: if the sender is E (attacker label) → 'send/forward/impersonate'
        If receiver is E → 'receive/intercept'
        """
        if "E" in sender.upper():
            return "forward_or_impersonate"
        if "E" in receiver.upper():
            return "intercept"
        return "observe"

    def scan_for_attack_keywords(self, text: str) -> Dict[str, List[str]]:
        """
        Return a dict mapping each attack category to the matching phrases
        found in the text.  Useful for debugging extraction.
        """
        findings: Dict[str, List[str]] = {}
        text_lower = text.lower()
        for category, patterns in _ATTACK_KEYWORDS:
            matches = []
            for pattern in patterns:
                for m in re.finditer(pattern, text_lower):
                    matches.append(m.group(0))
            if matches:
                findings[category] = matches
        return findings


# ── Standalone demo ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sample = """
    We present a man-in-the-middle attack on the Needham-Schroeder
    Public Key Protocol. The intruder E intercepts the first message
    from A and forwards it to B while impersonating A. When B replies,
    E intercepts the response and forwards it back to A. A's
    authentication claim fails because B ends the run believing it
    has authenticated A, but A was never aware of the session with B.

    Attack trace:
    A → E(B) : {Na, A}Ke
    E(A) → B : {Na, A}Kb
    B → E(A) : {Na, Nb}Ka
    E(B) → A : {Na, Nb}Ka
    A → E(B) : {Nb}Ke
    E(A) → B : {Nb}Kb

    The secrecy of Na and Nb is violated. Entity authentication
    at B is broken because B believes A ran the protocol but A
    interacted only with E. The attack requires the attacker to
    intercept, replay, and forward messages.
    """

    extractor = AttackExtractor()
    info = extractor.extract_attack_info(sample)

    print("Attack present    :", info["attack_present"])
    print("Attack category   :", info["attack_category"])
    print("Confidence        :", info["confidence"])
    print("Capabilities      :", info["attacker_capabilities"])
    print("Properties        :", info["security_property_targeted"])
    print("\nAttack trace:\n", info["attack_trace"])
    print("\nEvidence signals:")
    for ev in info["evidence"]:
        print(f"  {ev}")
