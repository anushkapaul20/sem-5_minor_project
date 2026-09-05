"""
tests/test_dolev_yao.py
=======================
Unit tests for engine/dolev_yao.py — AttackerKnowledge and deduction closure.
"""
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.terms import Atom, Concat, DH, Encrypt, Hash, Pair
from engine.dolev_yao import AttackerKnowledge, can_derive, closure


# ── Basic knows / add ──────────────────────────────────────────────────────────

def test_knows_atom_directly():
    atk = AttackerKnowledge([Atom("Na")])
    assert atk.knows(Atom("Na"))

def test_not_knows_unseen_atom():
    atk = AttackerKnowledge([Atom("Na")])
    assert not atk.knows(Atom("Nb"))

def test_add_returns_true_for_new():
    atk = AttackerKnowledge()
    assert atk.add(Atom("Na")) is True

def test_add_returns_false_for_duplicate():
    atk = AttackerKnowledge([Atom("Na")])
    assert atk.add(Atom("Na")) is False

def test_len_reflects_knowledge():
    atk = AttackerKnowledge([Atom("Na"), Atom("Nb")])
    assert len(atk) >= 2


# ── Concat decomposition ──────────────────────────────────────────────────────

def test_decompose_concat():
    Na, A = Atom("Na"), Atom("A")
    msg = Concat(Na, A)
    atk = AttackerKnowledge([msg])
    assert atk.knows(Na)
    assert atk.knows(A)

def test_decompose_nested_concat():
    Na, Nb, A = Atom("Na"), Atom("Nb"), Atom("A")
    msg = Concat(Na, Concat(Nb, A))
    atk = AttackerKnowledge([msg])
    assert atk.knows(Na)
    assert atk.knows(Nb)
    assert atk.knows(A)

def test_decompose_pair():
    Na, Nb = Atom("Na"), Atom("Nb")
    p = Pair(Na, Nb)
    atk = AttackerKnowledge([p])
    assert atk.knows(Na)
    assert atk.knows(Nb)


# ── Encrypt decomposition ─────────────────────────────────────────────────────

def test_decrypt_with_key():
    Na, Kb = Atom("Na"), Atom("Kb")
    msg = Encrypt(Na, Kb)
    atk = AttackerKnowledge([msg, Kb])
    assert atk.knows(Na)

def test_no_decrypt_without_key():
    Na, Kb = Atom("Na"), Atom("Kb")
    msg = Encrypt(Na, Kb)
    atk = AttackerKnowledge([msg])
    assert not atk.knows(Na)

def test_decrypt_after_adding_key():
    Na, Kb = Atom("Na"), Atom("Kb")
    msg = Encrypt(Na, Kb)
    atk = AttackerKnowledge([msg])
    assert not atk.knows(Na)
    atk.add(Kb)
    assert atk.knows(Na)

def test_decrypt_nested():
    Na, Ka, Kb = Atom("Na"), Atom("Ka"), Atom("Kb")
    inner = Encrypt(Na, Ka)
    outer = Encrypt(inner, Kb)
    atk = AttackerKnowledge([outer, Kb, Ka])
    assert atk.knows(Na)

def test_decrypt_only_inner_key():
    Na, Ka, Kb = Atom("Na"), Atom("Ka"), Atom("Kb")
    inner = Encrypt(Na, Ka)
    outer = Encrypt(inner, Kb)
    atk = AttackerKnowledge([outer, Kb])  # has Kb but NOT Ka
    assert atk.knows(inner)              # can get inner ciphertext
    assert not atk.knows(Na)             # cannot decrypt inner


# ── Hash ──────────────────────────────────────────────────────────────────────

def test_hash_not_invertible():
    Na = Atom("Na")
    h  = Hash(Na)
    atk = AttackerKnowledge([h])
    assert not atk.knows(Na)

def test_hash_known_directly():
    Na = Atom("Na")
    h  = Hash(Na)
    atk = AttackerKnowledge([h])
    assert atk.knows(h)


# ── can_build (composition) ───────────────────────────────────────────────────

def test_can_build_encrypt_from_parts():
    Na, Kb = Atom("Na"), Atom("Kb")
    atk = AttackerKnowledge([Na, Kb])
    assert atk.can_build(Encrypt(Na, Kb))

def test_can_build_concat_from_parts():
    Na, A = Atom("Na"), Atom("A")
    atk = AttackerKnowledge([Na, A])
    assert atk.can_build(Concat(Na, A))

def test_cannot_build_encrypt_missing_key():
    Na, Kb = Atom("Na"), Atom("Kb")
    atk = AttackerKnowledge([Na])
    assert not atk.can_build(Encrypt(Na, Kb))

def test_can_build_nested():
    Na, A, Kb = Atom("Na"), Atom("A"), Atom("Kb")
    atk = AttackerKnowledge([Na, A, Kb])
    assert atk.can_build(Encrypt(Concat(Na, A), Kb))


# ── DH ───────────────────────────────────────────────────────────────────────

def test_dh_cannot_extract_exponent():
    g, x = Atom("g"), Atom("x")
    gx = DH(g, x)
    atk = AttackerKnowledge([gx])
    assert not atk.knows(x)

def test_dh_equational_theory():
    g, x, y = Atom("g"), Atom("x"), Atom("y")
    gx = DH(g, x)
    gy = DH(g, y)
    atk = AttackerKnowledge([gx, gy, x, y])
    # Attacker can build g^(xy) and g^(yx)
    assert atk.can_build(DH(gx, y))
    assert atk.can_build(DH(gy, x))
    # They are equal under DH axiom
    from engine.terms import dh_equal
    assert dh_equal(DH(gx, y), DH(gy, x))


# ── learn_from ────────────────────────────────────────────────────────────────

def test_learn_from_returns_true_on_new():
    Na = Atom("Na")
    atk = AttackerKnowledge()
    assert atk.learn_from(Na) is True

def test_learn_from_returns_false_on_known():
    Na = Atom("Na")
    atk = AttackerKnowledge([Na])
    assert atk.learn_from(Na) is False

def test_learn_from_concat_expands():
    Na, A = Atom("Na"), Atom("A")
    atk = AttackerKnowledge()
    atk.learn_from(Concat(Na, A))
    assert atk.knows(Na)
    assert atk.knows(A)


# ── snapshot / copy ───────────────────────────────────────────────────────────

def test_snapshot_immutable():
    Na = Atom("Na")
    atk = AttackerKnowledge([Na])
    snap = atk.snapshot()
    atk.add(Atom("Nb"))
    assert Atom("Nb") not in snap  # snapshot not affected

def test_copy_independence():
    Na, Nb = Atom("Na"), Atom("Nb")
    atk = AttackerKnowledge([Na])
    atk2 = atk.copy()
    atk2.add(Nb)
    assert not atk.knows(Nb)   # original unaffected


# ── Module-level convenience ───────────────────────────────────────────────────

def test_can_derive_function():
    Na, Kb = Atom("Na"), Atom("Kb")
    msg = Encrypt(Na, Kb)
    assert can_derive([msg, Kb], Na)
    assert not can_derive([msg], Na)

def test_closure_function():
    Na, A, Kb = Atom("Na"), Atom("A"), Atom("Kb")
    msg = Concat(Na, A)
    cl = closure([msg])
    assert Na in cl
    assert A  in cl

def test_contains_operator():
    Na = Atom("Na")
    atk = AttackerKnowledge([Na])
    assert Na in atk


# ── NSPK scenario ─────────────────────────────────────────────────────────────

def test_nspk_attacker_knows_ke_decrypts_m1():
    """
    E intercepts M1: {Na, A}Ke — E can decrypt because E knows ke = Atom("Ke").
    (In the attack Ke is E's public key, ke is private key — same atom here.)
    """
    Na, A, Ke = Atom("Na"), Atom("A"), Atom("Ke")
    m1 = Encrypt(Concat(Na, A), Ke)
    atk = AttackerKnowledge([m1, Ke])
    assert atk.knows(Na)
    assert atk.knows(A)

def test_nspk_attacker_cannot_decrypt_m2():
    """
    M2: {Na, Nb}Ka — attacker does NOT know Ka, cannot decrypt.
    """
    Na, Nb, Ka = Atom("Na"), Atom("Nb"), Atom("Ka")
    m2 = Encrypt(Concat(Na, Nb), Ka)
    atk = AttackerKnowledge([m2])
    assert not atk.knows(Nb)
