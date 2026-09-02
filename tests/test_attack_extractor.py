"""
tests/test_attack_extractor.py
================================
Unit tests for attack_extractor.py — keyword detection, confidence
scoring, and attack trace extraction.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from extraction.attack_extractor import AttackExtractor


@pytest.fixture
def extractor():
    return AttackExtractor()


# ── No-signal text ────────────────────────────────────────────────────────────

def test_no_signals_returns_no_attack(extractor):
    result = extractor.extract_attack_info("The quick brown fox jumps over the lazy dog.")
    assert result["attack_present"] == 0
    assert result["confidence"] == "NONE"
    assert result["attack_category"] == ["None"]


# ── MITM detection ────────────────────────────────────────────────────────────

def test_mitm_keyword_detected(extractor):
    result = extractor.extract_attack_info(
        "The paper presents a man-in-the-middle attack on the protocol."
    )
    assert result["attack_present"] == 1
    assert "MITM" in result["attack_category"]


def test_mitm_abbreviation_detected(extractor):
    result = extractor.extract_attack_info("The MITM attack succeeds against this scheme.")
    assert "MITM" in result["attack_category"]


# ── Replay detection ──────────────────────────────────────────────────────────

def test_replay_keyword_detected(extractor):
    result = extractor.extract_attack_info(
        "An attacker can mount a replay attack by replaying old messages."
    )
    assert "Replay" in result["attack_category"]


# ── Reflection detection ──────────────────────────────────────────────────────

def test_reflection_keyword_detected(extractor):
    result = extractor.extract_attack_info(
        "The reflection attack exploits parallel sessions."
    )
    assert "Reflection" in result["attack_category"]


# ── UKS detection ─────────────────────────────────────────────────────────────

def test_uks_keyword_detected(extractor):
    result = extractor.extract_attack_info(
        "This demonstrates an unknown key share attack on STS."
    )
    assert "UKS" in result["attack_category"]


# ── KCI detection ─────────────────────────────────────────────────────────────

def test_kci_keyword_detected(extractor):
    result = extractor.extract_attack_info(
        "The key compromise impersonation attack is demonstrated."
    )
    assert "KCI" in result["attack_category"]


# ── Secrecy violation detection ───────────────────────────────────────────────

def test_secrecy_violation_detected(extractor):
    result = extractor.extract_attack_info(
        "The session key is revealed to the attacker by this attack."
    )
    assert "Secrecy_Violation" in result["attack_category"]


# ── Attacker capability detection ────────────────────────────────────────────

def test_intercept_capability(extractor):
    result = extractor.extract_attack_info(
        "The adversary intercepts messages on the channel."
    )
    assert "intercept" in result["attacker_capabilities"]


def test_replay_capability(extractor):
    result = extractor.extract_attack_info(
        "The attacker replays an old message to the server."
    )
    assert "replay" in result["attacker_capabilities"]


def test_impersonate_capability(extractor):
    result = extractor.extract_attack_info(
        "E impersonates Alice to Bob during the protocol run."
    )
    assert "impersonate" in result["attacker_capabilities"]


# ── Security property detection ───────────────────────────────────────────────

def test_authentication_property(extractor):
    result = extractor.extract_attack_info(
        "The authentication property is violated by this attack."
    )
    assert "authentication" in result["security_property_targeted"]


def test_secrecy_property(extractor):
    result = extractor.extract_attack_info(
        "The secrecy of the session key is broken."
    )
    assert "secrecy" in result["security_property_targeted"]


def test_forward_secrecy_property(extractor):
    result = extractor.extract_attack_info(
        "The protocol does not provide perfect forward secrecy."
    )
    assert "forward_secrecy" in result["security_property_targeted"]


# ── Confidence levels ─────────────────────────────────────────────────────────

def test_confidence_high_with_multiple_signals(extractor):
    text = (
        "The man-in-the-middle attack is demonstrated. "
        "The attacker intercepts and modifies messages. "
        "The authentication property is violated. "
        "A → E(B) : {Na, A}Kb\n"
        "E(A) → B : {Na, A}Kb"
    )
    result = extractor.extract_attack_info(text)
    assert result["confidence"] in ("HIGH", "MEDIUM")


def test_confidence_low_single_keyword(extractor):
    result = extractor.extract_attack_info("A replay attack may occur.")
    assert result["confidence"] in ("LOW", "MEDIUM", "HIGH")
    assert result["attack_present"] == 1


# ── Attack trace extraction ───────────────────────────────────────────────────

def test_attack_trace_lines_extracted(extractor):
    text = """
    The attacker mounts a MITM attack.
    A → E(B) : {Na, A}Kb
    E(A) → B : {Na, A}Kb
    B → E(A) : {Na, Nb}Ka
    """
    result = extractor.extract_attack_info(text)
    assert len(result["attack_trace"]) > 0
    assert "→" in result["attack_trace"] or "->" in result["attack_trace"]


def test_no_trace_when_no_arrows(extractor):
    result = extractor.extract_attack_info(
        "The man-in-the-middle attack intercepts messages."
    )
    assert result["attack_trace"] == ""


# ── needs_review always True for auto-extracted ──────────────────────────────

def test_needs_review_always_true(extractor):
    result = extractor.extract_attack_info("Any text here.")
    assert result["needs_review"] is True


# ── scan_for_attack_keywords ──────────────────────────────────────────────────

def test_scan_keywords_returns_dict(extractor):
    findings = extractor.scan_for_attack_keywords(
        "The replay attack and man-in-the-middle attack are shown."
    )
    assert isinstance(findings, dict)
    assert "Replay" in findings
    assert "MITM" in findings


def test_scan_keywords_empty_on_no_match(extractor):
    findings = extractor.scan_for_attack_keywords("Hello world.")
    assert findings == {}


# ── Structured trace extraction ───────────────────────────────────────────────

def test_extract_structured_trace(extractor):
    trace = """
    Step 1: A → E : {Na, A}Kb
    Step 2: E → B : {Na, A}Kb
    Step 3: B → E : {Na, Nb}Ka
    """
    structured = extractor.extract_attack_trace_structured(trace)
    assert len(structured) == 3
    assert structured[0]["step"] == 1
    assert structured[0]["sender"] == "A"
