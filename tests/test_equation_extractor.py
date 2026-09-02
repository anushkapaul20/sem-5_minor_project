"""
tests/test_equation_extractor.py
=================================
Unit tests for equation_extractor.py — arrow-notation parsing,
payload decomposition, primitive detection, participant normalisation.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from extraction.equation_extractor import EquationExtractor, ParsedMessage


@pytest.fixture
def extractor():
    return EquationExtractor()


# ── Basic arrow-notation parsing ──────────────────────────────────────────────

def test_parse_single_message(extractor):
    msgs = extractor.extract("A → B : {Na, A}Kb")
    assert len(msgs) == 1
    m = msgs[0]
    assert m.sender == "A"
    assert m.receiver == "B"
    assert "{Na, A}Kb" in m.message


def test_parse_three_messages_nspk(extractor):
    text = """
    Message 1:  A → B : {Na, A}Kb
    Message 2:  B → A : {Na, Nb}Ka
    Message 3:  A → B : {Nb}Kb
    """
    msgs = extractor.extract(text)
    assert len(msgs) == 3
    assert msgs[0].step == 1
    assert msgs[1].step == 2
    assert msgs[2].step == 3


def test_parse_five_messages_nssk(extractor):
    text = """
    Message 1:  A → S : A, B, Na
    Message 2:  S → A : {Na, B, K_AB, {K_AB, A}K_BS}K_AS
    Message 3:  A → B : {K_AB, A}K_BS
    Message 4:  B → A : {Nb}K_AB
    Message 5:  A → B : {Nb - 1}K_AB
    """
    msgs = extractor.extract(text)
    assert len(msgs) == 5


def test_arrow_variants(extractor):
    texts = [
        "A → B : Na",
        "A -> B : Na",
        "A --> B : Na",
    ]
    for t in texts:
        msgs = extractor.extract(t)
        assert len(msgs) == 1, f"Failed for arrow variant in: {t!r}"


def test_step_prefix_variants(extractor):
    texts = [
        "Step 1: A → B : Na",
        "M1: A → B : Na",
        "1. A → B : Na",
        "(1) A → B : Na",
    ]
    for t in texts:
        msgs = extractor.extract(t)
        assert len(msgs) == 1 and msgs[0].step == 1, f"Failed for: {t!r}"


# ── Sender / receiver normalisation ──────────────────────────────────────────

def test_normalise_alice_bob(extractor):
    msgs = extractor.extract("Alice → Bob : Na")
    assert msgs[0].sender == "A"
    assert msgs[0].receiver == "B"


def test_normalise_server(extractor):
    msgs = extractor.extract("A → Server : Na")
    assert msgs[0].receiver == "S"


def test_normalise_eve(extractor):
    msgs = extractor.extract("Eve → Bob : Na")
    assert msgs[0].sender == "E"


# ── Protection type detection ─────────────────────────────────────────────────

def test_public_key_encryption_detected(extractor):
    # Ka, Kb — single party key → public key encryption
    msgs = extractor.extract("A → B : {Na, A}Kb")
    assert msgs[0].protection == "public_key_encryption"
    assert msgs[0].key == "Kb"


def test_symmetric_encryption_detected(extractor):
    msgs = extractor.extract("A → B : {K_AB, A}K_BS")
    assert msgs[0].protection == "symmetric_encryption"


def test_hash_detected(extractor):
    msgs = extractor.extract("A → B : H(Na, Nb)")
    assert msgs[0].protection == "hash"


def test_plaintext_detected(extractor):
    msgs = extractor.extract("A → S : A, B, Na")
    assert msgs[0].protection == "plaintext"


def test_dh_step_detected(extractor):
    msgs = extractor.extract("A → B : g^x")
    assert msgs[0].is_dh_step is True
    assert len(msgs[0].dh_values) > 0


# ── Payload splitting ─────────────────────────────────────────────────────────

def test_payload_split_simple(extractor):
    msgs = extractor.extract("A → S : A, B, Na")
    assert "A" in msgs[0].payload_items
    assert "B" in msgs[0].payload_items
    assert "Na" in msgs[0].payload_items


def test_payload_split_respects_braces(extractor):
    # {Na, A}Kb should be ONE item, not split on the inner comma
    msgs = extractor.extract("A → B : {Na, A}Kb, Nb")
    assert len(msgs[0].payload_items) == 2
    assert any("{Na, A}Kb" in item for item in msgs[0].payload_items)
    assert "Nb" in msgs[0].payload_items


# ── Nonce detection ───────────────────────────────────────────────────────────

def test_nonce_detection(extractor):
    msgs = extractor.extract("A → B : {Na, Nb}Ka")
    nonces = msgs[0].nonces
    assert "Na" in nonces
    assert "Nb" in nonces


# ── equations_only extraction ────────────────────────────────────────────────

def test_extract_equations_only(extractor):
    text = """
    This is a description of the protocol.
    Message 1: A → B : {Na, A}Kb
    The attacker intercepts this.
    Message 2: B → A : {Na, Nb}Ka
    """
    eqs = extractor.extract_equations_only(text)
    assert len(eqs) == 2
    assert all("→" in eq or "->" in eq for eq in eqs)


# ── Primitive identification ──────────────────────────────────────────────────

def test_identify_dh_primitive(extractor):
    text = "A → B : g^x"
    prims = extractor.identify_primitives(text)
    assert "Diffie-Hellman" in prims


def test_identify_nonce_primitive(extractor):
    text = "A → B : {Na, A}Kb"
    prims = extractor.identify_primitives(text)
    assert "Nonce" in prims


def test_identify_hash_primitive(extractor):
    text = "A → B : H(Na, Nb)"
    prims = extractor.identify_primitives(text)
    assert "Hash" in prims


def test_identify_multiple_primitives(extractor):
    text = "A → B : {Na, A}Kb\nB → A : {Na, Nb}Ka"
    prims = extractor.identify_primitives(text)
    assert "Nonce" in prims
    assert "Public_Key_Encryption" in prims


# ── Empty / no-match input ────────────────────────────────────────────────────

def test_empty_text_returns_empty(extractor):
    assert extractor.extract("") == []


def test_no_arrows_returns_empty(extractor):
    assert extractor.extract("This text has no protocol messages.") == []


def test_partial_arrow_not_matched(extractor):
    # No colon after arrow — should not match
    msgs = extractor.extract("A → B")
    assert len(msgs) == 0


# ── STS protocol ─────────────────────────────────────────────────────────────

def test_sts_three_steps(extractor):
    text = """
    Step 1: A → B : g^x
    Step 2: B → A : g^y, Cert_B, {sig_B(g^y || g^x)}K
    Step 3: A → B : Cert_A, {sig_A(g^x || g^y)}K
    """
    msgs = extractor.extract(text)
    assert len(msgs) == 3
    assert msgs[0].is_dh_step is True


# ── Auto step numbering when no prefix ───────────────────────────────────────

def test_auto_step_numbering(extractor):
    text = "A → B : Na\nB → A : Nb\nA → B : Na2"
    msgs = extractor.extract(text)
    assert [m.step for m in msgs] == [1, 2, 3]
