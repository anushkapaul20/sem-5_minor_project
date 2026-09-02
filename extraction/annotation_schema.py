"""
annotation_schema.py
====================
Defines the canonical data model for every dataset record.

A ProtocolRecord is a Python dataclass covering all 48 fields from
DATA_DICTIONARY.md.  It includes:
  - field-level type hints
  - default values (None / empty list where optional)
  - a validate() method that checks required fields and controlled
    vocabulary compliance
  - a to_dict() / from_dict() round-trip for JSON serialisation
  - an EMPTY_RECORD factory for the human annotation workflow

ANTI-FABRICATION RULE
---------------------
Every field that cannot be confirmed from the source paper MUST be set to
one of:
  extraction_status = "REQUIRES_REVIEW"
  equation_status   = "REQUIRES_REVIEW"
  attack_status     = "REQUIRES_REVIEW"
and the text of the field itself must be:
  "REQUIRES_MANUAL_VERIFICATION"
Never use a placeholder value that looks real.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import date
from typing import Any, List, Optional

# ── Controlled Vocabularies ──────────────────────────────────────────────────

ATTACK_CATEGORIES = {
    "MITM",
    "Replay",
    "Reflection",
    "Impersonation",
    "UKS",
    "Secrecy_Violation",
    "Authentication_Violation",
    "Session_Key_Compromise",
    "KCI",
    "Forward_Secrecy_Violation",
    "None",
}

EXTRACTION_STATUS_VALUES = {
    "AUTO_EXTRACTED",
    "HUMAN_VERIFIED",
    "REQUIRES_REVIEW",
}

FIELD_STATUS_VALUES = {
    "FOUND",
    "NOT_FOUND",
    "HUMAN_VERIFIED",
    "REQUIRES_REVIEW",
    "UNAVAILABLE",
}

SCYTHER_RESULT_VALUES = {
    "VERIFIED_SECURE",
    "ATTACK_FOUND",
    "NOT_RUN",
    "TIMEOUT",
    "PARSE_ERROR",
    "REQUIRES_REVIEW",
}

SOURCE_TYPE_VALUES = {
    "conference_paper",
    "journal_article",
    "thesis",
    "technical_report",
    "textbook",
    "rfc",
    "standard",
}

PROTOCOL_TYPE_VALUES = {
    "authentication",
    "key_exchange",
    "key_agreement",
    "authenticated_key_exchange",
    "password_authentication",
    "group_key_agreement",
    "session_establishment",
}

ATTACKER_CAPABILITY_VALUES = {
    "intercept",
    "modify",
    "replay",
    "forward",
    "reflect",
    "impersonate",
    "block",
    "compute",
    "compromise_key",
}

SECURITY_PROPERTY_VALUES = {
    "secrecy",
    "authentication",
    "forward_secrecy",
    "key_freshness",
    "mutual_authentication",
    "non_repudiation",
    "key_confirmation",
    "anonymity",
    "entity_authentication",
    "key_establishment",
}

PRIMITIVE_VALUES = {
    "RSA",
    "Diffie-Hellman",
    "ECDH",
    "ECC",
    "AES",
    "DES",
    "3DES",
    "Hash",
    "HMAC",
    "MAC",
    "Digital_Signature",
    "Public_Key_Encryption",
    "Symmetric_Encryption",
    "Nonce",
    "Timestamp",
    "Password",
    "Shared_Secret",
    "Session_Key",
    "Certificate",
    "Challenge_Response",
}

# ── Validation Error ─────────────────────────────────────────────────────────

class ValidationError(Exception):
    """Raised when a ProtocolRecord fails field validation."""
    pass


# ── Main Dataclass ───────────────────────────────────────────────────────────

@dataclass
class ProtocolRecord:
    """
    One row in the cryptographic protocol attack dataset.
    Corresponds exactly to the schema in DATA_DICTIONARY.md v0.1.
    """

    # ── Paper / Source Metadata ──────────────────────────────────────────────
    paper_id: str = ""
    paper_title: str = ""
    authors: str = ""
    publication_year: Optional[int] = None
    source_link: str = "UNAVAILABLE"
    source_type: str = ""
    source_page: str = "REQUIRES_MANUAL_VERIFICATION"
    equation_source_page: str = "REQUIRES_MANUAL_VERIFICATION"
    attack_source_page: str = "REQUIRES_MANUAL_VERIFICATION"

    # ── Protocol Identity ────────────────────────────────────────────────────
    protocol_name: str = ""
    protocol_type: str = ""
    protocol_variant: str = ""

    # ── Protocol Participants ────────────────────────────────────────────────
    participants: List[str] = field(default_factory=list)
    participant_count: int = 0
    trusted_third_party: bool = False

    # ── Cryptographic Primitives ─────────────────────────────────────────────
    cryptographic_primitives: List[str] = field(default_factory=list)
    cryptographic_parameters: str = ""

    # ── Protocol Equations ───────────────────────────────────────────────────
    original_equations: str = "REQUIRES_MANUAL_VERIFICATION"
    normalized_equations: List[dict] = field(default_factory=list)

    # ── Message Flow ─────────────────────────────────────────────────────────
    message_1: str = ""
    message_2: str = ""
    message_3: str = ""
    message_4: str = ""
    message_5: str = ""
    complete_message_flow: List[dict] = field(default_factory=list)
    message_step_count: int = 0

    # ── Attacker Model ───────────────────────────────────────────────────────
    attacker_model: str = "Dolev-Yao"
    attacker_identity: str = "outsider"
    attacker_capabilities: List[str] = field(default_factory=list)

    # ── Attack Information ───────────────────────────────────────────────────
    attack_name: str = "None"
    attack_category: List[str] = field(default_factory=lambda: ["None"])
    attack_present: int = 0
    protocol_secure: bool = True
    attacker_action: List[str] = field(default_factory=list)

    # ── Attack Trace ─────────────────────────────────────────────────────────
    attack_trace: str = ""
    attack_trace_structured: List[dict] = field(default_factory=list)

    # ── Security Properties ──────────────────────────────────────────────────
    security_property_targeted: List[str] = field(default_factory=list)
    security_violation: str = ""

    # ── Scyther Integration ──────────────────────────────────────────────────
    scyther_model_available: bool = False
    scyther_model_path: str = ""
    scyther_verification_result: str = "NOT_RUN"
    scyther_attack_trace: str = ""

    # ── Extraction Metadata ──────────────────────────────────────────────────
    extraction_status: str = "REQUIRES_REVIEW"
    equation_status: str = "REQUIRES_REVIEW"
    attack_status: str = "REQUIRES_REVIEW"
    extraction_date: str = ""
    last_verified_date: str = ""
    verified_by: str = ""
    notes: str = ""

    # ── Validation ───────────────────────────────────────────────────────────

    def validate(self) -> List[str]:
        """
        Check all required fields and controlled vocabulary compliance.

        Returns a list of error strings.  Empty list = record is valid.
        Does NOT raise — caller decides whether to treat errors as fatal.
        """
        errors: List[str] = []

        # Required non-empty fields
        required_non_empty = [
            ("paper_id", self.paper_id),
            ("paper_title", self.paper_title),
            ("authors", self.authors),
            ("protocol_name", self.protocol_name),
            ("extraction_status", self.extraction_status),
        ]
        for fname, fval in required_non_empty:
            if not fval or not str(fval).strip():
                errors.append(f"REQUIRED field '{fname}' is empty.")

        # Required integer / boolean fields
        if self.publication_year is not None:
            if not (1900 <= self.publication_year <= 2100):
                errors.append(
                    f"'publication_year' value {self.publication_year} is outside "
                    f"plausible range 1900–2100."
                )

        if self.attack_present not in (0, 1):
            errors.append(
                f"'attack_present' must be 0 or 1, got {self.attack_present!r}."
            )

        # Controlled vocabulary: extraction_status
        if self.extraction_status not in EXTRACTION_STATUS_VALUES:
            errors.append(
                f"'extraction_status' value {self.extraction_status!r} not in "
                f"{sorted(EXTRACTION_STATUS_VALUES)}."
            )

        # Controlled vocabulary: equation_status
        if self.equation_status not in FIELD_STATUS_VALUES:
            errors.append(
                f"'equation_status' value {self.equation_status!r} not in "
                f"{sorted(FIELD_STATUS_VALUES)}."
            )

        # Controlled vocabulary: attack_status
        if self.attack_status not in FIELD_STATUS_VALUES:
            errors.append(
                f"'attack_status' value {self.attack_status!r} not in "
                f"{sorted(FIELD_STATUS_VALUES)}."
            )

        # Controlled vocabulary: scyther_verification_result
        if self.scyther_verification_result not in SCYTHER_RESULT_VALUES:
            errors.append(
                f"'scyther_verification_result' value "
                f"{self.scyther_verification_result!r} not in "
                f"{sorted(SCYTHER_RESULT_VALUES)}."
            )

        # Controlled vocabulary: source_type
        if self.source_type and self.source_type not in SOURCE_TYPE_VALUES:
            errors.append(
                f"'source_type' value {self.source_type!r} not in "
                f"{sorted(SOURCE_TYPE_VALUES)}."
            )

        # Controlled vocabulary: protocol_type
        if self.protocol_type and self.protocol_type not in PROTOCOL_TYPE_VALUES:
            errors.append(
                f"'protocol_type' value {self.protocol_type!r} not in "
                f"{sorted(PROTOCOL_TYPE_VALUES)}."
            )

        # Controlled vocabulary: attack_category (each element)
        for cat in self.attack_category:
            if cat not in ATTACK_CATEGORIES:
                errors.append(
                    f"'attack_category' entry {cat!r} not in "
                    f"{sorted(ATTACK_CATEGORIES)}."
                )

        # Consistency: attack_present=0 means category must be ["None"]
        if self.attack_present == 0:
            if self.attack_category != ["None"]:
                errors.append(
                    "When 'attack_present'=0, 'attack_category' must be [\"None\"]. "
                    f"Got {self.attack_category!r}."
                )
            if self.protocol_secure is False:
                errors.append(
                    "When 'attack_present'=0, 'protocol_secure' should be True."
                )

        if self.attack_present == 1 and "None" in self.attack_category:
            errors.append(
                "When 'attack_present'=1, 'attack_category' must not contain \"None\"."
            )

        # Controlled vocabulary: attacker_capabilities (each element)
        for cap in self.attacker_capabilities:
            if cap not in ATTACKER_CAPABILITY_VALUES:
                errors.append(
                    f"'attacker_capabilities' entry {cap!r} not in "
                    f"{sorted(ATTACKER_CAPABILITY_VALUES)}."
                )

        # Controlled vocabulary: cryptographic_primitives (each element)
        for prim in self.cryptographic_primitives:
            if prim not in PRIMITIVE_VALUES:
                errors.append(
                    f"'cryptographic_primitives' entry {prim!r} not in "
                    f"controlled vocabulary."
                )

        # Controlled vocabulary: security_property_targeted (each element)
        for prop in self.security_property_targeted:
            if prop not in SECURITY_PROPERTY_VALUES:
                errors.append(
                    f"'security_property_targeted' entry {prop!r} not in "
                    f"{sorted(SECURITY_PROPERTY_VALUES)}."
                )

        # Consistency: participant_count vs len(participants)
        if self.participants and self.participant_count != len(self.participants):
            errors.append(
                f"'participant_count' ({self.participant_count}) does not match "
                f"len(participants) ({len(self.participants)})."
            )

        # Anti-fabrication check: look for forbidden markers
        forbidden = {"FABRICATED", "INVENTED", "MADE_UP"}
        all_text = (
            self.original_equations
            + self.attack_trace
            + self.security_violation
            + self.notes
        )
        for marker in forbidden:
            if marker in all_text.upper():
                errors.append(
                    f"Anti-fabrication marker {marker!r} found in record text."
                )

        # complete_message_flow structure check
        for i, step in enumerate(self.complete_message_flow):
            if not isinstance(step, dict):
                errors.append(
                    f"'complete_message_flow[{i}]' must be a dict, got {type(step).__name__}."
                )
            else:
                for required_key in ("step", "sender", "receiver", "message"):
                    if required_key not in step:
                        errors.append(
                            f"'complete_message_flow[{i}]' missing key '{required_key}'."
                        )

        return errors

    def validate_strict(self) -> None:
        """Validate and raise ValidationError if any errors found."""
        errors = self.validate()
        if errors:
            raise ValidationError(
                f"Record '{self.paper_id}' failed validation with "
                f"{len(errors)} error(s):\n" + "\n".join(f"  - {e}" for e in errors)
            )

    # ── Serialisation ────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Convert to a plain dict (JSON-serialisable)."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ProtocolRecord":
        """
        Reconstruct a ProtocolRecord from a plain dict.
        Unknown keys are silently ignored to allow forward-compatibility.
        """
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)

    def to_json(self, indent: int = 2) -> str:
        """Serialise to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str) -> "ProtocolRecord":
        return cls.from_dict(json.loads(json_str))

    # ── Convenience ──────────────────────────────────────────────────────────

    def is_verified(self) -> bool:
        """True only if the record has been human-verified."""
        return self.extraction_status == "HUMAN_VERIFIED"

    def needs_review(self) -> bool:
        """True if the record requires human attention."""
        return self.extraction_status == "REQUIRES_REVIEW"

    def summary(self) -> str:
        """One-line human-readable summary."""
        attack_str = ", ".join(self.attack_category)
        return (
            f"[{self.paper_id}] {self.protocol_name} | "
            f"attack_present={self.attack_present} | "
            f"categories={attack_str} | "
            f"status={self.extraction_status}"
        )

    def __repr__(self) -> str:
        return (
            f"ProtocolRecord(paper_id={self.paper_id!r}, "
            f"protocol_name={self.protocol_name!r}, "
            f"attack_present={self.attack_present})"
        )


# ── Factory: empty annotation template ───────────────────────────────────────

def empty_record(paper_id: str = "", today: Optional[str] = None) -> ProtocolRecord:
    """
    Return a blank ProtocolRecord ready for manual annotation.
    All fields are set to their 'unknown' sentinel values so nothing
    looks accidentally real.
    """
    today_str = today or date.today().isoformat()
    return ProtocolRecord(
        paper_id=paper_id,
        paper_title="REQUIRES_MANUAL_VERIFICATION",
        authors="REQUIRES_MANUAL_VERIFICATION",
        publication_year=None,
        source_link="UNAVAILABLE",
        source_type="",
        source_page="REQUIRES_MANUAL_VERIFICATION",
        equation_source_page="REQUIRES_MANUAL_VERIFICATION",
        attack_source_page="REQUIRES_MANUAL_VERIFICATION",
        protocol_name="REQUIRES_MANUAL_VERIFICATION",
        protocol_type="",
        protocol_variant="",
        participants=[],
        participant_count=0,
        trusted_third_party=False,
        cryptographic_primitives=[],
        cryptographic_parameters="",
        original_equations="REQUIRES_MANUAL_VERIFICATION",
        normalized_equations=[],
        message_1="",
        message_2="",
        message_3="",
        message_4="",
        message_5="",
        complete_message_flow=[],
        message_step_count=0,
        attacker_model="Dolev-Yao",
        attacker_identity="outsider",
        attacker_capabilities=[],
        attack_name="None",
        attack_category=["None"],
        attack_present=0,
        protocol_secure=True,
        attacker_action=[],
        attack_trace="",
        attack_trace_structured=[],
        security_property_targeted=[],
        security_violation="",
        scyther_model_available=False,
        scyther_model_path="",
        scyther_verification_result="NOT_RUN",
        scyther_attack_trace="",
        extraction_status="REQUIRES_REVIEW",
        equation_status="REQUIRES_REVIEW",
        attack_status="REQUIRES_REVIEW",
        extraction_date=today_str,
        last_verified_date="",
        verified_by="",
        notes="",
    )


# ── CSV column order (matches DATA_DICTIONARY.md) ────────────────────────────

CSV_COLUMNS: List[str] = [
    "paper_id", "paper_title", "authors", "publication_year",
    "source_link", "source_type", "source_page",
    "equation_source_page", "attack_source_page",
    "protocol_name", "protocol_type", "protocol_variant",
    "participants", "participant_count", "trusted_third_party",
    "cryptographic_primitives", "cryptographic_parameters",
    "original_equations", "normalized_equations",
    "message_1", "message_2", "message_3", "message_4", "message_5",
    "complete_message_flow", "message_step_count",
    "attacker_model", "attacker_identity", "attacker_capabilities",
    "attack_name", "attack_category", "attack_present", "protocol_secure",
    "attacker_action",
    "attack_trace", "attack_trace_structured",
    "security_property_targeted", "security_violation",
    "scyther_model_available", "scyther_model_path",
    "scyther_verification_result", "scyther_attack_trace",
    "extraction_status", "equation_status", "attack_status",
    "extraction_date", "last_verified_date", "verified_by", "notes",
]

assert len(CSV_COLUMNS) == 49, f"Expected 49 columns, got {len(CSV_COLUMNS)}"
# NOTE: DATA_DICTIONARY.md defines 48 fields; attack_trace_structured was added
# in schema v0.1 as an extension. DATA_DICTIONARY.md will be updated in Phase 1B.
