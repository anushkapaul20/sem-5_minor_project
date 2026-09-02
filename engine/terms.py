"""
engine/terms.py
===============
Term algebra for the QuantumScyther AI verification engine.

Every value that appears in a cryptographic protocol — a nonce,
a key, an encrypted message, a hash — is represented as a Term.
The engine manipulates Terms symbolically; it never works with
concrete byte values.

Term hierarchy
--------------
    Term (base)
    ├── Atom          — irreducible value: nonce, key, identity, literal
    ├── Encrypt       — {payload}key  (symmetric or public-key)
    ├── Hash          — H(content)
    ├── Concat        — left || right  (concatenation / pairing)
    ├── DH            — g^exponent mod p  (Diffie-Hellman)
    └── Pair          — (left, right)  (ordered pair, alias for Concat)

Dolev-Yao decomposition rules (implemented in dolev_yao.py):
    Encrypt(m, k)  → can extract m  IF  attacker knows k
    Concat(a, b)   → can extract a AND b  always
    Pair(a, b)     → can extract a AND b  always
    Hash(m)        → cannot invert
    DH(g, x)       → cannot extract x  (DLP hardness)
    Atom           → cannot decompose further

DH equational theory:
    DH(DH(g, x), y) == DH(DH(g, y), x)   (g^(xy) == g^(yx))
    This is the ONLY equational axiom — hardcoded as a special case.

Usage
-----
    from engine.terms import Atom, Encrypt, Hash, Concat, DH

    Na = Atom("Na")
    Kb = Atom("Kb")
    msg = Encrypt(Concat(Na, Atom("A")), Kb)
    print(msg)          # Encrypt(Concat(Atom(Na), Atom(A)), Atom(Kb))
    print(msg == msg)   # True
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet, Set, Tuple


# ── Base class ────────────────────────────────────────────────────────────────

@dataclass(frozen=True, eq=True)
class Term:
    """
    Abstract base for all symbolic terms.
    All Term subclasses are immutable (frozen=True) and hashable,
    so they can be stored in sets and used as dict keys.
    """

    def subterms(self) -> FrozenSet["Term"]:
        """Return all subterms including self (for knowledge closure)."""
        raise NotImplementedError

    def __repr__(self) -> str:
        raise NotImplementedError


# ── Atom ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, eq=True)
class Atom(Term):
    """
    An irreducible symbolic value.
    Examples: Atom("Na"), Atom("Kb"), Atom("A"), Atom("g")

    Atoms represent:
      - Nonces      (Na, Nb, Ns ...)
      - Keys        (Ka, Kb, K_AB, K_AS ...)
      - Identities  (A, B, S, E ...)
      - Constants   (g for DH generator, any literal)
    """
    name: str

    def subterms(self) -> FrozenSet[Term]:
        return frozenset({self})

    def __repr__(self) -> str:
        return f"Atom({self.name})"

    def __str__(self) -> str:
        return self.name


# ── Encrypt ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True, eq=True)
class Encrypt(Term):
    """
    Encrypted message: {payload}key

    Represents both symmetric and public-key encryption.
    The engine does not distinguish them at the term level —
    the distinction is captured in the protocol model.

    Dolev-Yao rule:
      The attacker can extract `payload` from Encrypt(payload, key)
      IF AND ONLY IF the attacker knows `key`.
    """
    payload: Term
    key: Term

    def subterms(self) -> FrozenSet[Term]:
        return frozenset({self}) | self.payload.subterms() | self.key.subterms()

    def __repr__(self) -> str:
        return f"Encrypt({self.payload!r}, {self.key!r})"

    def __str__(self) -> str:
        return f"{{{self.payload}}}{self.key}"


# ── Hash ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, eq=True)
class Hash(Term):
    """
    Cryptographic hash: H(content)

    Dolev-Yao rule:
      - The attacker CAN compute Hash(m) for any m it knows.
      - The attacker CANNOT invert Hash — cannot recover m from Hash(m).
    """
    content: Term

    def subterms(self) -> FrozenSet[Term]:
        # Note: content subterms are NOT exposed (hash is one-way)
        return frozenset({self})

    def __repr__(self) -> str:
        return f"Hash({self.content!r})"

    def __str__(self) -> str:
        return f"H({self.content})"


# ── Concat ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, eq=True)
class Concat(Term):
    """
    Concatenation of two terms: left || right

    Dolev-Yao rule:
      The attacker can ALWAYS extract both `left` and `right`
      from Concat(left, right) — no key needed.
    """
    left: Term
    right: Term

    def subterms(self) -> FrozenSet[Term]:
        return frozenset({self}) | self.left.subterms() | self.right.subterms()

    def __repr__(self) -> str:
        return f"Concat({self.left!r}, {self.right!r})"

    def __str__(self) -> str:
        return f"({self.left} || {self.right})"


# ── Pair ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, eq=True)
class Pair(Term):
    """
    Ordered pair: (first, second)

    Semantically identical to Concat for Dolev-Yao purposes.
    Provided as a separate class for protocol models that use
    pair/tuple notation rather than concatenation.

    Dolev-Yao rule: same as Concat — both components always extractable.
    """
    first: Term
    second: Term

    def subterms(self) -> FrozenSet[Term]:
        return frozenset({self}) | self.first.subterms() | self.second.subterms()

    def __repr__(self) -> str:
        return f"Pair({self.first!r}, {self.second!r})"

    def __str__(self) -> str:
        return f"({self.first}, {self.second})"


# ── DH ───────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, eq=True)
class DH(Term):
    """
    Diffie-Hellman exponentiation: base^exponent  (i.e. g^x)

    Dolev-Yao rule:
      - The attacker CAN compute DH(base, exp) for any base/exp it knows.
      - The attacker CANNOT extract `exponent` from DH(base, exponent)
        (discrete logarithm hardness assumption).

    DH equational theory (the ONLY equation hardcoded):
      DH(DH(g, x), y) == DH(DH(g, y), x)
      i.e. g^(xy) == g^(yx)

    This is handled by dh_equal() below, NOT by __eq__,
    because __eq__ must be structurally strict for hashing.
    Use dh_equal() whenever checking DH key agreement.
    """
    base: Term
    exponent: Term

    def subterms(self) -> FrozenSet[Term]:
        # Only the whole DH term is exposed; exponent is not recoverable
        return frozenset({self})

    def __repr__(self) -> str:
        return f"DH({self.base!r}, {self.exponent!r})"

    def __str__(self) -> str:
        return f"{self.base}^{self.exponent}"


# ── DH equational theory ──────────────────────────────────────────────────────

def dh_equal(t1: Term, t2: Term) -> bool:
    """
    Check whether two terms are equal under the DH equational theory:
        DH(DH(g, x), y) == DH(DH(g, y), x)

    Structural equality is always checked first.
    Then the DH commutativity case is checked.

    Parameters
    ----------
    t1, t2 : Term

    Returns
    -------
    bool — True if t1 and t2 are equal (structurally or via DH axiom)
    """
    if t1 == t2:
        return True

    # DH commutativity: DH(DH(g, x), y) == DH(DH(g, y), x)
    if isinstance(t1, DH) and isinstance(t2, DH):
        b1, e1 = t1.base, t1.exponent
        b2, e2 = t2.base, t2.exponent
        # Both are of the form g^(xy) and g^(yx)?
        if isinstance(b1, DH) and isinstance(b2, DH):
            # t1 = DH(DH(g, x), y),  t2 = DH(DH(g, y), x)
            if (b1.base == b2.base        # same generator g
                    and b1.exponent == e2  # x matches
                    and b2.exponent == e1):  # y matches
                return True

    return False


# ── Utility: flatten Concat / Pair to a list ─────────────────────────────────

def flatten_concat(term: Term) -> list[Term]:
    """
    Flatten nested Concat/Pair into a flat list of components.

    Example:
        Concat(Atom("Na"), Concat(Atom("Nb"), Atom("A")))
        → [Atom("Na"), Atom("Nb"), Atom("A")]
    """
    if isinstance(term, (Concat, Pair)):
        left_items = flatten_concat(term.left if isinstance(term, Concat) else term.first)
        right_items = flatten_concat(term.right if isinstance(term, Concat) else term.second)
        return left_items + right_items
    return [term]


def build_concat(terms: list[Term]) -> Term:
    """
    Build a right-nested Concat from a list of terms.

    Example:
        [Na, Nb, A] → Concat(Na, Concat(Nb, A))
    """
    if not terms:
        raise ValueError("Cannot build Concat from empty list.")
    if len(terms) == 1:
        return terms[0]
    return Concat(terms[0], build_concat(terms[1:]))


# ── Standalone demo ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    Na = Atom("Na")
    Nb = Atom("Nb")
    Ka = Atom("Ka")
    Kb = Atom("Kb")
    A  = Atom("A")
    g  = Atom("g")
    x  = Atom("x")
    y  = Atom("y")

    # NSPK Message 1: {Na, A}Kb
    msg1 = Encrypt(Concat(Na, A), Kb)
    print("NSPK M1:", msg1)

    # NSPK Message 2: {Na, Nb}Ka
    msg2 = Encrypt(Concat(Na, Nb), Ka)
    print("NSPK M2:", msg2)

    # Hash
    h = Hash(Concat(Na, Nb))
    print("Hash   :", h)

    # DH key exchange
    gx = DH(g, x)
    gy = DH(g, y)
    shared1 = DH(gx, y)   # g^(xy)
    shared2 = DH(gy, x)   # g^(yx)
    print("DH g^x :", gx)
    print("DH g^y :", gy)
    print("g^(xy) == g^(yx) via dh_equal:", dh_equal(shared1, shared2))

    # Subterms
    print("\nSubterms of msg1:")
    for t in sorted(msg1.subterms(), key=repr):
        print(" ", t)

    # Flatten
    triple = build_concat([Na, Nb, A])
    print("\nbuild_concat([Na, Nb, A]):", triple)
    print("flatten_concat result    :", flatten_concat(triple))
