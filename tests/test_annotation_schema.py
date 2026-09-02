"""
tests/test_annotation_schema.py
================================
Unit tests for annotation_schema.py — ProtocolRecord validation,
serialisation, and factory functions.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from extraction.annotation_schema import (
    CSV_COLUMNS,
    ProtocolRecord,
    ValidationError,
    empty_record,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _minimal_valid_record(**kwargs) -> ProtocolRecord:
    """Return a minimally valid ProtocolRecord (attack_present=0)."""
    defaults = dict(
        paper_id="paper_test",
        paper_title="Test Paper",
        authors="Test Author",
        publication_year=2020,
        protocol_name="Test Protocol",
        source_type="journal_article",
        protocol_type="authentication",
        attack_present=0,
        attack_category=["None"],
        protocol_secure=True,
        extraction_status="HUMAN_VERIFIED",
        equation_status="FOUND",
        attack_status="FOUND",
    )
    defaults.update(kwargs)
    return ProtocolRecord(**defaults)


# ── CSV columns ───────────────────────────────────────────────────────────────

def test_csv_columns_count():
    assert len(CSV_COLUMNS) == 49


def test_csv_columns_no_duplicates():
    assert len(CSV_COLUMNS) == len(set(CSV_COLUMNS))


# ── empty_record factory ──────────────────────────────────────────────────────

def test_empty_record_has_paper_id():
    r = empty_record("paper_xyz")
    assert r.paper_id == "paper_xyz"


def test_empty_record_attack_present_zero():
    r = empty_record("p1")
    assert r.attack_present == 0


def test_empty_record_requires_review():
    r = empty_record("p1")
    assert r.extraction_status == "REQUIRES_REVIEW"


# ── Basic validation: required fields ─────────────────────────────────────────

def test_valid_minimal_record():
    r = _minimal_valid_record()
    errors = r.validate()
    assert errors == [], f"Unexpected errors: {errors}"


def test_missing_paper_id():
    r = _minimal_valid_record(paper_id="")
    errors = r.validate()
    assert any("paper_id" in e for e in errors)


def test_missing_paper_title():
    r = _minimal_valid_record(paper_title="")
    errors = r.validate()
    assert any("paper_title" in e for e in errors)


def test_missing_protocol_name():
    r = _minimal_valid_record(protocol_name="")
    errors = r.validate()
    assert any("protocol_name" in e for e in errors)


# ── Controlled vocabulary: extraction_status ──────────────────────────────────

def test_valid_extraction_status_values():
    for status in ("AUTO_EXTRACTED", "HUMAN_VERIFIED", "REQUIRES_REVIEW"):
        r = _minimal_valid_record(extraction_status=status)
        errors = r.validate()
        assert not any("extraction_status" in e for e in errors)


def test_invalid_extraction_status():
    r = _minimal_valid_record(extraction_status="DONE")
    errors = r.validate()
    assert any("extraction_status" in e for e in errors)


# ── Controlled vocabulary: attack_category ────────────────────────────────────

def test_valid_attack_categories():
    valid_cats = [
        "MITM", "Replay", "Reflection", "Impersonation", "UKS",
        "Secrecy_Violation", "Authentication_Violation",
        "Session_Key_Compromise", "KCI", "Forward_Secrecy_Violation",
    ]
    for cat in valid_cats:
        r = _minimal_valid_record(
            attack_present=1,
            attack_category=[cat],
            protocol_secure=False,
        )
        errors = r.validate()
        assert not any("attack_category" in e for e in errors), \
            f"Valid category {cat!r} raised error: {errors}"


def test_invalid_attack_category():
    r = _minimal_valid_record(
        attack_present=1,
        attack_category=["NotAnAttack"],
        protocol_secure=False,
    )
    errors = r.validate()
    assert any("attack_category" in e for e in errors)


def test_multi_label_attack_category():
    r = _minimal_valid_record(
        attack_present=1,
        attack_category=["MITM", "Impersonation"],
        protocol_secure=False,
    )
    errors = r.validate()
    assert not any("attack_category" in e for e in errors)


# ── Consistency: attack_present vs attack_category ────────────────────────────

def test_attack_present_0_must_have_none_category():
    r = _minimal_valid_record(
        attack_present=0,
        attack_category=["MITM"],  # wrong
        protocol_secure=True,
    )
    errors = r.validate()
    assert any("attack_category" in e or "None" in e for e in errors)


def test_attack_present_1_must_not_have_none_category():
    r = _minimal_valid_record(
        attack_present=1,
        attack_category=["None"],  # wrong
        protocol_secure=False,
    )
    errors = r.validate()
    assert any("None" in e for e in errors)


def test_attack_present_0_protocol_secure_false_warns():
    r = _minimal_valid_record(
        attack_present=0,
        attack_category=["None"],
        protocol_secure=False,  # inconsistent
    )
    errors = r.validate()
    assert any("protocol_secure" in e for e in errors)


# ── Attacker capabilities ─────────────────────────────────────────────────────

def test_valid_attacker_capabilities():
    for cap in ("intercept", "modify", "replay", "forward", "reflect",
                "impersonate", "block", "compute", "compromise_key"):
        r = _minimal_valid_record(attacker_capabilities=[cap])
        errors = r.validate()
        assert not any("attacker_capabilities" in e for e in errors), \
            f"Valid capability {cap!r} raised: {errors}"


def test_invalid_attacker_capability():
    r = _minimal_valid_record(attacker_capabilities=["fly"])
    errors = r.validate()
    assert any("attacker_capabilities" in e for e in errors)


# ── participant_count consistency ─────────────────────────────────────────────

def test_participant_count_mismatch():
    r = _minimal_valid_record(
        participants=["A", "B"],
        participant_count=3,  # wrong
    )
    errors = r.validate()
    assert any("participant_count" in e for e in errors)


def test_participant_count_correct():
    r = _minimal_valid_record(
        participants=["A", "B"],
        participant_count=2,
    )
    errors = r.validate()
    assert not any("participant_count" in e for e in errors)


# ── Anti-fabrication markers ──────────────────────────────────────────────────

def test_fabrication_marker_blocked():
    r = _minimal_valid_record(notes="FABRICATED value here")
    errors = r.validate()
    assert any("fabrication" in e.lower() or "FABRICATED" in e for e in errors)


# ── Serialisation round-trip ──────────────────────────────────────────────────

def test_to_dict_round_trip():
    r = _minimal_valid_record(
        participants=["A", "B"],
        participant_count=2,
        cryptographic_primitives=["Nonce", "Public_Key_Encryption"],
    )
    d = r.to_dict()
    r2 = ProtocolRecord.from_dict(d)
    assert r2.paper_id == r.paper_id
    assert r2.participants == r.participants
    assert r2.cryptographic_primitives == r.cryptographic_primitives


def test_json_round_trip():
    r = _minimal_valid_record(
        attack_present=1,
        attack_category=["Replay"],
        protocol_secure=False,
    )
    json_str = r.to_json()
    r2 = ProtocolRecord.from_json(json_str)
    assert r2.attack_present == 1
    assert r2.attack_category == ["Replay"]


def test_from_dict_ignores_unknown_keys():
    r = _minimal_valid_record()
    d = r.to_dict()
    d["UNKNOWN_FUTURE_FIELD"] = "something"
    r2 = ProtocolRecord.from_dict(d)
    assert r2.paper_id == r.paper_id


# ── validate_strict ───────────────────────────────────────────────────────────

def test_validate_strict_raises():
    r = _minimal_valid_record(paper_id="")
    with pytest.raises(ValidationError):
        r.validate_strict()


def test_validate_strict_passes():
    r = _minimal_valid_record()
    r.validate_strict()  # should not raise


# ── complete_message_flow structure check ────────────────────────────────────

def test_message_flow_valid():
    r = _minimal_valid_record(
        complete_message_flow=[
            {"step": 1, "sender": "A", "receiver": "B", "message": "{Na}Kb"},
        ]
    )
    errors = r.validate()
    assert not any("complete_message_flow" in e for e in errors)


def test_message_flow_missing_key():
    r = _minimal_valid_record(
        complete_message_flow=[
            {"step": 1, "sender": "A", "message": "{Na}Kb"},  # missing receiver
        ]
    )
    errors = r.validate()
    assert any("complete_message_flow" in e for e in errors)


# ── summary / repr ────────────────────────────────────────────────────────────

def test_summary_returns_string():
    r = _minimal_valid_record()
    s = r.summary()
    assert isinstance(s, str)
    assert "paper_test" in s


def test_repr():
    r = _minimal_valid_record()
    assert "ProtocolRecord" in repr(r)
