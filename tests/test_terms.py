"""
tests/test_terms.py
===================
Unit tests for engine/terms.py — Term algebra, subterms,
DH equational theory, flatten/build_concat, unifier.
"""
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.terms import (
    Atom, Concat, DH, Encrypt, Hash, Pair, Term,
    build_concat, dh_equal, flatten_concat,
)
from engine.unifier import Variable, match, substitute, free_variables


# ── Atom ──────────────────────────────────────────────────────────────────────

def test_atom_repr():
    assert repr(Atom("Na")) == "Atom(Na)"

def test_atom_str():
    assert str(Atom("Na")) == "Na"

def test_atom_equality():
    assert Atom("Na") == Atom("Na")
    assert Atom("Na") != Atom("Nb")

def test_atom_hashable():
    s = {Atom("Na"), Atom("Na"), Atom("Nb")}
    assert len(s) == 2

def test_atom_subterms():
    assert Atom("Na").subterms() == frozenset({Atom("Na")})


# ── Encrypt ───────────────────────────────────────────────────────────────────

def test_encrypt_repr():
    e = Encrypt(Atom("Na"), Atom("Kb"))
    assert "Encrypt" in repr(e)

def test_encrypt_str():
    e = Encrypt(Atom("Na"), Atom("Kb"))
    assert "{Na}Kb" in str(e) or "Na" in str(e)

def test_encrypt_equality():
    e1 = Encrypt(Atom("Na"), Atom("Kb"))
    e2 = Encrypt(Atom("Na"), Atom("Kb"))
    assert e1 == e2

def test_encrypt_inequality_payload():
    e1 = Encrypt(Atom("Na"), Atom("Kb"))
    e2 = Encrypt(Atom("Nb"), Atom("Kb"))
    assert e1 != e2

def test_encrypt_inequality_key():
    e1 = Encrypt(Atom("Na"), Atom("Ka"))
    e2 = Encrypt(Atom("Na"), Atom("Kb"))
    assert e1 != e2

def test_encrypt_subterms():
    e = Encrypt(Atom("Na"), Atom("Kb"))
    st = e.subterms()
    assert e in st
    assert Atom("Na") in st
    assert Atom("Kb") in st

def test_encrypt_nested_subterms():
    inner = Encrypt(Atom("Na"), Atom("Ka"))
    outer = Encrypt(inner, Atom("Kb"))
    st = outer.subterms()
    assert outer in st
    assert inner in st
    assert Atom("Na") in st


# ── Concat ────────────────────────────────────────────────────────────────────

def test_concat_subterms():
    c = Concat(Atom("Na"), Atom("A"))
    assert Atom("Na") in c.subterms()
    assert Atom("A") in c.subterms()

def test_concat_equality():
    assert Concat(Atom("Na"), Atom("A")) == Concat(Atom("Na"), Atom("A"))
    assert Concat(Atom("Na"), Atom("A")) != Concat(Atom("A"), Atom("Na"))

def test_concat_hashable():
    s = {Concat(Atom("Na"), Atom("A"))}
    assert len(s) == 1


# ── Hash ──────────────────────────────────────────────────────────────────────

def test_hash_str():
    h = Hash(Atom("Na"))
    assert "H(" in str(h)

def test_hash_subterms_one_way():
    h = Hash(Atom("Na"))
    # Hash is one-way: content NOT in subterms (cannot invert)
    assert Atom("Na") not in h.subterms()
    assert h in h.subterms()

def test_hash_equality():
    assert Hash(Atom("Na")) == Hash(Atom("Na"))
    assert Hash(Atom("Na")) != Hash(Atom("Nb"))


# ── DH ───────────────────────────────────────────────────────────────────────

def test_dh_str():
    g, x = Atom("g"), Atom("x")
    assert "g^x" in str(DH(g, x)) or "g" in str(DH(g, x))

def test_dh_subterms_one_way():
    g, x = Atom("g"), Atom("x")
    gx = DH(g, x)
    # DLP: exponent NOT in subterms
    assert x not in gx.subterms()
    assert gx in gx.subterms()

def test_dh_equality_structural():
    g, x = Atom("g"), Atom("x")
    assert DH(g, x) == DH(g, x)
    assert DH(g, x) != DH(g, Atom("y"))


# ── DH equational theory ──────────────────────────────────────────────────────

def test_dh_equal_reflexive():
    g, x, y = Atom("g"), Atom("x"), Atom("y")
    shared = DH(DH(g, x), y)
    assert dh_equal(shared, shared)

def test_dh_equal_commutativity():
    g, x, y = Atom("g"), Atom("x"), Atom("y")
    gxy = DH(DH(g, x), y)   # g^(xy)
    gyx = DH(DH(g, y), x)   # g^(yx)
    assert dh_equal(gxy, gyx)

def test_dh_equal_different_generator():
    g1, g2 = Atom("g"), Atom("h")
    x, y = Atom("x"), Atom("y")
    assert not dh_equal(DH(DH(g1, x), y), DH(DH(g2, y), x))

def test_dh_equal_atoms():
    assert dh_equal(Atom("Na"), Atom("Na"))
    assert not dh_equal(Atom("Na"), Atom("Nb"))


# ── Pair ──────────────────────────────────────────────────────────────────────

def test_pair_subterms():
    p = Pair(Atom("Na"), Atom("Nb"))
    assert Atom("Na") in p.subterms()
    assert Atom("Nb") in p.subterms()


# ── build_concat / flatten_concat ─────────────────────────────────────────────

def test_build_concat_single():
    t = build_concat([Atom("Na")])
    assert t == Atom("Na")

def test_build_concat_two():
    t = build_concat([Atom("Na"), Atom("A")])
    assert t == Concat(Atom("Na"), Atom("A"))

def test_build_concat_three():
    t = build_concat([Atom("Na"), Atom("Nb"), Atom("A")])
    assert t == Concat(Atom("Na"), Concat(Atom("Nb"), Atom("A")))

def test_flatten_concat_simple():
    t = Concat(Atom("Na"), Atom("A"))
    assert flatten_concat(t) == [Atom("Na"), Atom("A")]

def test_flatten_concat_nested():
    t = Concat(Atom("Na"), Concat(Atom("Nb"), Atom("A")))
    assert flatten_concat(t) == [Atom("Na"), Atom("Nb"), Atom("A")]

def test_flatten_single():
    assert flatten_concat(Atom("Na")) == [Atom("Na")]

def test_build_empty_raises():
    with pytest.raises(ValueError):
        build_concat([])

def test_build_flatten_roundtrip():
    items = [Atom("Na"), Atom("Nb"), Atom("A")]
    assert flatten_concat(build_concat(items)) == items


# ── Variable ─────────────────────────────────────────────────────────────────

def test_variable_repr():
    v = Variable("Na")
    assert "Var(Na)" in repr(v)

def test_variable_str():
    v = Variable("Na")
    assert "?Na" in str(v)

def test_variable_hashable():
    s = {Variable("x"), Variable("x"), Variable("y")}
    assert len(s) == 2


# ── match ─────────────────────────────────────────────────────────────────────

def test_match_atom_success():
    env = match(Atom("Na"), Atom("Na"))
    assert env is not None

def test_match_atom_fail():
    assert match(Atom("Na"), Atom("Nb")) is None

def test_match_variable_binds():
    env = match(Variable("x"), Atom("Na"))
    assert env == {"x": Atom("Na")}

def test_match_variable_consistent():
    # ?x bound to Na, then ?x appears again — must match Na
    pattern = Concat(Variable("x"), Variable("x"))
    env = match(pattern, Concat(Atom("Na"), Atom("Na")))
    assert env is not None and env["x"] == Atom("Na")

def test_match_variable_inconsistent():
    pattern = Concat(Variable("x"), Variable("x"))
    assert match(pattern, Concat(Atom("Na"), Atom("Nb"))) is None

def test_match_encrypt_success():
    Ka = Atom("Ka");  Na = Atom("Na");  Nb = Atom("Nb")
    pattern  = Encrypt(Concat(Variable("Na"), Variable("Nb")), Ka)
    concrete = Encrypt(Concat(Na, Nb), Ka)
    env = match(pattern, concrete)
    assert env is not None
    assert env["Na"] == Na
    assert env["Nb"] == Nb

def test_match_encrypt_wrong_key():
    Ka = Atom("Ka");  Kb = Atom("Kb")
    pattern  = Encrypt(Variable("m"), Ka)
    concrete = Encrypt(Atom("Na"), Kb)
    assert match(pattern, concrete) is None

def test_match_type_mismatch():
    assert match(Atom("Na"), Encrypt(Atom("Na"), Atom("K"))) is None


# ── substitute ────────────────────────────────────────────────────────────────

def test_substitute_atom_no_change():
    t = substitute(Atom("Na"), {"x": Atom("Nb")})
    assert t == Atom("Na")

def test_substitute_variable():
    t = substitute(Variable("x"), {"x": Atom("Na")})
    assert t == Atom("Na")

def test_substitute_unbound_variable():
    t = substitute(Variable("x"), {})
    assert t == Variable("x")

def test_substitute_encrypt():
    pattern = Encrypt(Variable("m"), Atom("Ka"))
    result  = substitute(pattern, {"m": Atom("Na")})
    assert result == Encrypt(Atom("Na"), Atom("Ka"))

def test_substitute_nested():
    pattern = Encrypt(Concat(Variable("Na"), Variable("Nb")), Atom("Ka"))
    result  = substitute(pattern, {"Na": Atom("Na1"), "Nb": Atom("Nb1")})
    assert result == Encrypt(Concat(Atom("Na1"), Atom("Nb1")), Atom("Ka"))


# ── free_variables ────────────────────────────────────────────────────────────

def test_free_variables_none():
    assert free_variables(Atom("Na")) == frozenset()

def test_free_variables_one():
    assert free_variables(Variable("x")) == frozenset({"x"})

def test_free_variables_nested():
    t = Encrypt(Concat(Variable("Na"), Atom("A")), Variable("K"))
    fv = free_variables(t)
    assert fv == frozenset({"Na", "K"})

def test_free_variables_duplicate():
    t = Concat(Variable("x"), Variable("x"))
    assert free_variables(t) == frozenset({"x"})
