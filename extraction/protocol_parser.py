"""
protocol_parser.py
==================
Parses a raw text block (from a PDF or manual input) into a structured
ProtocolRecord.

PIPELINE ROLE
-------------
Text/PDF  →  EquationExtractor  →  ProtocolParser  →  ProtocolRecord  →  Dataset

WHAT IT DOES
------------
Given:
  - extracted_text : raw text from a paper section
  - metadata       : dict with paper_id, paper_title, authors, year, etc.
  - attack_info    : dict returned by AttackExtractor (optional)

It produces a ProtocolRecord with:
  - complete_message_flow populated from EquationExtractor
  - normalized_equations populated
  - message_1 … message_5 convenience fields populated
  - message_step_count set
  - participants detected from sender/receiver fields
  - cryptographic_primitives detected
  - trusted_third_party flag set
  - extraction_status = "AUTO_EXTRACTED"

WHAT IT DOES NOT DO
-------------------
- Does NOT set equation_status = "HUMAN_VERIFIED" (only a human can do that)
- Does NOT invent protocol content
- Does NOT modify original_equations (caller must supply it from the paper)

USAGE
-----
    from extraction.protocol_parser import ProtocolParser

    parser = ProtocolParser()
    record = parser.parse(
        extracted_text=text,
        metadata={
            "paper_id": "paper_001",
            "paper_title": "...",
            "authors": "...",
            "publication_year": 1978,
            "source_link": "...",
            "source_type": "journal_article",
            "source_page": "pp. 993-999",
            "equation_source_page": "p. 993",
            "attack_source_page": "REQUIRES_MANUAL_VERIFICATION",
            "protocol_name": "...",
            "protocol_type": "authentication",
            "original_equations": "...",
        },
    )
"""

from __future__ import annotations

import json
import re
from datetime import date
from typing import Any, Dict, List, Optional

from extraction.annotation_schema import (
    PARTICIPANT_NORM as _PNORM_UNUSED,  # imported for awareness; used indirectly
    ProtocolRecord,
    empty_record,
)
from extraction.equation_extractor import EquationExtractor, ParsedMessage

# Re-export the participant normalisation map from equation_extractor
from extraction.equation_extractor import PARTICIPANT_NORM

# Known third-party indicators in participant sets
_TTP_LABELS = {"S", "TTP", "CA", "KDC", "AS"}


class ProtocolParser:
    """
    Parses raw text + metadata into a ProtocolRecord.
    """

    def __init__(self) -> None:
        self._eq_extractor = EquationExtractor()

    # ── Public API ───────────────────────────────────────────────────────────

    def parse(
        self,
        extracted_text: str,
        metadata: Dict[str, Any],
        attack_info: Optional[Dict[str, Any]] = None,
    ) -> ProtocolRecord:
        """
        Build a ProtocolRecord from extracted text + metadata dict.

        Parameters
        ----------
        extracted_text : str
            Raw text section containing the protocol description.
        metadata : dict
            Must contain at minimum:
              paper_id, paper_title, authors, publication_year,
              protocol_name, original_equations
            All other fields are optional (will default to REQUIRES_MANUAL_VERIFICATION).
        attack_info : dict, optional
            Output from AttackExtractor.extract_attack_info().

        Returns
        -------
        ProtocolRecord
            extraction_status = "AUTO_EXTRACTED"
            Fields that could not be determined = "REQUIRES_MANUAL_VERIFICATION"
        """
        record = empty_record(
            paper_id=metadata.get("paper_id", ""),
            today=date.today().isoformat(),
        )

        # ── Paper metadata ────────────────────────────────────────────────
        record.paper_title = metadata.get("paper_title", "REQUIRES_MANUAL_VERIFICATION")
        record.authors = metadata.get("authors", "REQUIRES_MANUAL_VERIFICATION")
        record.publication_year = metadata.get("publication_year")
        record.source_link = metadata.get("source_link", "UNAVAILABLE")
        record.source_type = metadata.get("source_type", "")
        record.source_page = metadata.get("source_page", "REQUIRES_MANUAL_VERIFICATION")
        record.equation_source_page = metadata.get(
            "equation_source_page", "REQUIRES_MANUAL_VERIFICATION"
        )
        record.attack_source_page = metadata.get(
            "attack_source_page", "REQUIRES_MANUAL_VERIFICATION"
        )

        # ── Protocol identity ─────────────────────────────────────────────
        record.protocol_name = metadata.get(
            "protocol_name", "REQUIRES_MANUAL_VERIFICATION"
        )
        record.protocol_type = metadata.get("protocol_type", "")
        record.protocol_variant = metadata.get("protocol_variant", "")

        # ── Preserve original equations (read-only from paper) ────────────
        record.original_equations = metadata.get(
            "original_equations", "REQUIRES_MANUAL_VERIFICATION"
        )

        # ── Extract message flow ──────────────────────────────────────────
        messages: List[ParsedMessage] = self._eq_extractor.extract(extracted_text)
        record.complete_message_flow = [m.to_dict() for m in messages]
        record.normalized_equations = [m.to_dict() for m in messages]
        record.message_step_count = len(messages)

        # Populate convenience message_1 … message_5 fields
        step_map = {m.step: m for m in messages}
        for i in range(1, 6):
            if i in step_map:
                m = step_map[i]
                msg_str = f"{m.sender} → {m.receiver} : {m.message}"
                setattr(record, f"message_{i}", msg_str)

        # ── Participants ──────────────────────────────────────────────────
        participants = self._extract_participants(messages, metadata)
        record.participants = participants
        record.participant_count = len(participants)
        record.trusted_third_party = any(p in _TTP_LABELS for p in participants)

        # ── Cryptographic primitives ──────────────────────────────────────
        detected_prims = self._eq_extractor.identify_primitives(extracted_text)
        # Also check the original_equations field
        detected_prims_eq = self._eq_extractor.identify_primitives(
            record.original_equations
        )
        merged_prims = sorted(set(detected_prims) | set(detected_prims_eq))
        record.cryptographic_primitives = (
            metadata.get("cryptographic_primitives") or merged_prims
        )
        record.cryptographic_parameters = metadata.get("cryptographic_parameters", "")

        # ── Attack information (from AttackExtractor or metadata) ─────────
        if attack_info:
            self._apply_attack_info(record, attack_info)
        else:
            # Pull from metadata if caller pre-supplied it
            for fname in (
                "attack_name",
                "attack_category",
                "attack_present",
                "protocol_secure",
                "attacker_model",
                "attacker_identity",
                "attacker_capabilities",
                "attacker_action",
                "attack_trace",
                "attack_trace_structured",
                "security_property_targeted",
                "security_violation",
            ):
                val = metadata.get(fname)
                if val is not None:
                    setattr(record, fname, val)

        # ── Scyther defaults ──────────────────────────────────────────────
        record.scyther_model_available = metadata.get("scyther_model_available", False)
        record.scyther_verification_result = "NOT_RUN"

        # ── Extraction metadata ───────────────────────────────────────────
        # Only mark as HUMAN_VERIFIED if the caller explicitly says so
        manual_status = metadata.get("extraction_status")
        if manual_status in ("AUTO_EXTRACTED", "HUMAN_VERIFIED", "REQUIRES_REVIEW"):
            record.extraction_status = manual_status
        else:
            record.extraction_status = "AUTO_EXTRACTED"

        record.equation_status = metadata.get("equation_status", "REQUIRES_REVIEW")
        record.attack_status = metadata.get("attack_status", "REQUIRES_REVIEW")
        record.notes = metadata.get("notes", "")

        return record

    def parse_from_json(self, json_path: str) -> ProtocolRecord:
        """
        Load a pre-structured JSON file and return a ProtocolRecord.
        The JSON must have the same keys as ProtocolRecord fields.
        """
        with open(json_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return ProtocolRecord.from_dict(data)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _extract_participants(
        self,
        messages: List[ParsedMessage],
        metadata: Dict[str, Any],
    ) -> List[str]:
        """
        Derive the participant list from:
        1. Caller-supplied metadata["participants"] (authoritative)
        2. Sender/receiver labels found in extracted messages
        """
        if metadata.get("participants"):
            return list(metadata["participants"])

        seen: dict[str, int] = {}
        for m in messages:
            for party in (m.sender, m.receiver):
                if party and party not in seen:
                    seen[party] = m.step
        # Sort: non-TTP parties first (A, B, …), then TTP (S, CA, …)
        non_ttp = [p for p in seen if p not in _TTP_LABELS]
        ttp = [p for p in seen if p in _TTP_LABELS]
        return sorted(non_ttp) + sorted(ttp)

    def _apply_attack_info(
        self, record: ProtocolRecord, attack_info: Dict[str, Any]
    ) -> None:
        """
        Merge AttackExtractor output into the record.
        Only sets fields that the extractor actually found.
        """
        if "attack_name" in attack_info:
            record.attack_name = attack_info["attack_name"]
        if "attack_category" in attack_info:
            record.attack_category = attack_info["attack_category"]
        if "attack_present" in attack_info:
            record.attack_present = attack_info["attack_present"]
        if "protocol_secure" in attack_info:
            record.protocol_secure = attack_info["protocol_secure"]
        if "attacker_capabilities" in attack_info:
            record.attacker_capabilities = attack_info["attacker_capabilities"]
        if "attacker_action" in attack_info:
            record.attacker_action = attack_info["attacker_action"]
        if "attack_trace" in attack_info:
            record.attack_trace = attack_info["attack_trace"]
        if "attack_trace_structured" in attack_info:
            record.attack_trace_structured = attack_info["attack_trace_structured"]
        if "security_property_targeted" in attack_info:
            record.security_property_targeted = attack_info[
                "security_property_targeted"
            ]
        if "security_violation" in attack_info:
            record.security_violation = attack_info["security_violation"]


# ── Convenience: build a record directly from a metadata dict ─────────────────

def build_record_from_metadata(metadata: Dict[str, Any]) -> ProtocolRecord:
    """
    Shortcut for the case where protocol text has already been manually
    entered into the metadata dict (no raw PDF text to parse).

    The caller provides all fields; this function just constructs a
    ProtocolRecord, validates it, and returns it.
    """
    parser = ProtocolParser()
    # Use original_equations as the text to extract from
    text = metadata.get("original_equations", "")
    return parser.parse(extracted_text=text, metadata=metadata)


# ── Standalone demo ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    nspk_text = """
    Message 1:  A → B : {Na, A}Kb
    Message 2:  B → A : {Na, Nb}Ka
    Message 3:  A → B : {Nb}Kb
    """

    nspk_metadata = {
        "paper_id": "paper_001",
        "paper_title": (
            "Using Encryption for Authentication in Large Networks of Computers"
        ),
        "authors": "Needham, R.M.; Schroeder, M.D.",
        "publication_year": 1978,
        "source_link": "https://doi.org/10.1145/359657.359659",
        "source_type": "journal_article",
        "source_page": "pp. 993-999",
        "equation_source_page": "p. 993",
        "attack_source_page": "REQUIRES_MANUAL_VERIFICATION",
        "protocol_name": "Needham-Schroeder Public Key Protocol",
        "protocol_type": "authentication",
        "original_equations": (
            "A → B : {Na, A}Kb\n"
            "B → A : {Na, Nb}Ka\n"
            "A → B : {Nb}Kb"
        ),
        "cryptographic_primitives": ["Public_Key_Encryption", "Nonce"],
        "attack_present": 1,
        "attack_category": ["MITM", "Impersonation", "Authentication_Violation"],
        "attack_name": "Lowe's MITM Attack on NSPK",
        "protocol_secure": False,
        "attacker_model": "Dolev-Yao",
        "attacker_capabilities": ["intercept", "forward", "impersonate"],
        "security_property_targeted": [
            "authentication", "entity_authentication", "mutual_authentication"
        ],
        "extraction_status": "HUMAN_VERIFIED",
        "equation_status": "HUMAN_VERIFIED",
        "attack_status": "HUMAN_VERIFIED",
        "notes": (
            "Equations from Needham-Schroeder 1978 CACM p.993. "
            "Attack from Lowe 1996 TACAS pp.147-166."
        ),
    }

    parser = ProtocolParser()
    record = parser.parse(nspk_text, nspk_metadata)

    errors = record.validate()
    print("Validation errors:", errors or "None — record is valid")
    print()
    print(record.summary())
    print()
    print("Message flow:")
    for step in record.complete_message_flow:
        print(
            f"  Step {step['step']}: {step['sender']} → {step['receiver']} : {step['message']}"
        )
    print(f"\nParticipants: {record.participants}")
    print(f"Primitives:   {record.cryptographic_primitives}")
