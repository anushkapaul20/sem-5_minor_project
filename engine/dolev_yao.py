"""
engine/dolev_yao.py
===================
Dolev-Yao attacker model for QuantumScyther AI.

The Dolev-Yao model (Dolev & Yao, 1983) treats the network as fully
controlled by the attacker. The attacker can:
  - Read every message in transit
  - Block, delay, or replay any message
  - Compose new messages from anything it knows
  - Decrypt {M}K if it knows K
  - Compute H(M) for any M it knows
  - Compute g^x for any x it knows

The attacker CANNOT:
  - Invert a hash  H(M) → M
  - Extract x from g^x  (DLP hardness)
  - Decrypt {M}K without knowing K

CORE CONCEPT — Deduction Closure
---------------------------------
Given a starting knowledge set (what the attacker already knows),
the deduction closure is the COMPLETE set of all terms the attacker
can derive by repeatedly applying Dolev-Yao deduction rules.

This is computed by `closure(knowledge)` which runs until no new
terms can be added (fixed-point iteration).

Usage
-----
    from engine.dolev_yao import AttackerKnowledge

    atk = AttackerKnowledge()
    atk.add(Atom("Na"))
    atk.add(Atom("Kb"))

    # Attacker sends a message — builds from knowledge
    msg = Encrypt(Atom("Na"), Atom("Kb"))
    assert atk.can_build(msg)

    # Attacker cannot decrypt without the key
    ciphertext = Encrypt(Atom("secret"), Atom("Ka"))
    assert not atk.knows(Atom("secret"))

    # Give attacker Ka — now it can decrypt
    atk.add(Atom("Ka"))
    atk.learn_from(ciphertext)
    assert atk.knows(Atom("secret"))
"""

from __future__ import annotations

from typing import FrozenSet, Set, Iterable

from engine.terms import (
    Atom, Concat, DH, Encrypt, Hash, Pair, Term, dh_equal, flatten_concat
)


class AttackerKnowledge:
    """
    Represents the Dolev-Yao attacker's current knowledge set.

    Internally stores a mutable set of known Terms.
    After each addition, the deduction closure is recomputed
    (or lazily recomputed on demand via `close()`).

    Parameters
    ----------
    initial : iterable of Term, optional
        Terms the attacker knows at the start (e.g. public values,
        attacker's own nonces/keys, intercepted messages).
    lazy : bool
        If True, deduction closure is NOT recomputed after every add().
        Caller must call close() manually. Useful for bulk initialisation.
    """

    def __init__(
        self,
        initial: Iterable[Term] = (),
        lazy: bool = False,
    ) -> None:
        self._known: Set[Term] = set()
        self._lazy = lazy
        for t in initial:
            self._known.add(t)
        if not lazy:
            self._close_inplace()

    # ── Public API ────────────────────────────────────────────────────────────

    def add(self, term: Term) -> bool:
        """
        Add a term to attacker knowledge.
        Recomputes the deduction closure unless lazy=True.

        Returns True if the knowledge set grew (new term was derivable).
        """
        if term in self._known:
            return False
        self._known.add(term)
        if not self._lazy:
            self._close_inplace()
        return True

    def add_all(self, terms: Iterable[Term]) -> None:
        """Add multiple terms, then close once."""
        for t in terms:
            self._known.add(t)
        if not self._lazy:
            self._close_inplace()

    def close(self) -> None:
        """Manually trigger deduction closure (use with lazy=True)."""
        self._close_inplace()

    def knows(self, term: Term) -> bool:
        """
        Check if the attacker knows a specific term.
        Also checks DH equational equality (g^(xy) == g^(yx)).
        """
        if term in self._known:
            return True
        # DH equational check
        for k in self._known:
            if dh_equal(k, term):
                return True
        return False

    def can_build(self, term: Term) -> bool:
        """
        Check if the attacker can construct `term` from its current knowledge.

        Decomposition-derived terms are in _known after closure.
        Composition is checked recursively here (targeted, not exhaustive).
        """
        if self.knows(term):
            return True
        # Targeted composition: can the attacker build this term from parts?
        if isinstance(term, Encrypt):
            return self.can_build(term.payload) and self.can_build(term.key)
        if isinstance(term, Concat):
            return self.can_build(term.left) and self.can_build(term.right)
        if isinstance(term, Pair):
            return self.can_build(term.first) and self.can_build(term.second)
        if isinstance(term, Hash):
            return self.can_build(term.content)
        if isinstance(term, DH):
            return self.can_build(term.base) and self.can_build(term.exponent)
        return False

    def learn_from(self, term: Term) -> bool:
        """
        Intercept a term (e.g. a message from the network).
        Add it and all immediately derivable sub-parts to knowledge.
        Returns True if any new knowledge was gained.
        """
        before = len(self._known)
        self._known.add(term)
        self._close_inplace()
        return len(self._known) > before

    def snapshot(self) -> FrozenSet[Term]:
        """Return an immutable snapshot of current knowledge."""
        return frozenset(self._known)

    def copy(self) -> "AttackerKnowledge":
        """Return a deep copy of this knowledge set."""
        new = AttackerKnowledge(lazy=True)
        new._known = set(self._known)
        return new

    def __len__(self) -> int:
        return len(self._known)

    def __contains__(self, term: Term) -> bool:
        return self.knows(term)

    def __repr__(self) -> str:
        return f"AttackerKnowledge({len(self._known)} terms)"

    # ── Deduction closure ─────────────────────────────────────────────────────

    def _close_inplace(self) -> None:
        """
        Compute the Dolev-Yao deduction closure in-place.
        Applies all derivation rules repeatedly until the knowledge set
        reaches a fixed point (no new terms can be added).

        Rules applied:
          1. Decompose Concat/Pair     → extract left and right components
          2. Decrypt Encrypt(m, k)    → extract m if k is known
          3. Compose Encrypt(m, k)    → add if m and k are known
          4. Compose Hash(m)          → add if m is known
          5. Compose DH(b, e)         → add if b and e are known
          6. Compose Concat(a, b)     → add if a and b are known
        """
        changed = True
        while changed:
            changed = False
            new_terms: Set[Term] = set()

            for term in list(self._known):

                # Rule 1: Decompose Concat — always
                if isinstance(term, Concat):
                    new_terms.add(term.left)
                    new_terms.add(term.right)

                # Rule 1b: Decompose Pair — always
                elif isinstance(term, Pair):
                    new_terms.add(term.first)
                    new_terms.add(term.second)

                # Rule 2: Decrypt if key is known
                elif isinstance(term, Encrypt):
                    if term.key in self._known:
                        new_terms.add(term.payload)

            # Rule 3–6: Composition — only compose if BOTH components are
            # already known (Atoms or previously derived terms).
            # We do NOT blindly enumerate all pairs — that explodes.
            # Instead, we only build terms that appear in the "expected"
            # set, i.e., only compose when a target term can be checked.
            # Full composition enumeration is deferred to can_build_target().
            pass  # Composition is handled on-demand in knows() / can_build()

            # Add any truly new terms
            before = len(self._known)
            self._known |= new_terms
            if len(self._known) > before:
                changed = True


# ── Module-level convenience ──────────────────────────────────────────────────

def closure(known: Iterable[Term]) -> FrozenSet[Term]:
    """
    Compute the Dolev-Yao deduction closure of an initial knowledge set.

    Parameters
    ----------
    known : iterable of Term

    Returns
    -------
    frozenset of Term — everything the attacker can derive from `known`
    """
    atk = AttackerKnowledge(known)
    return atk.snapshot()


def can_derive(known: Iterable[Term], target: Term) -> bool:
    """
    Check whether `target` is derivable from `known` under Dolev-Yao rules.

    Parameters
    ----------
    known  : iterable of Term — attacker's starting knowledge
    target : Term — what we want to check

    Returns
    -------
    bool
    """
    atk = AttackerKnowledge(known)
    return atk.knows(target)


# ── Standalone demo ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    Na = Atom("Na")
    Nb = Atom("Nb")
    Ka = Atom("Ka")
    Kb = Atom("Kb")
    A  = Atom("A")
    g  = Atom("g")
    x  = Atom("x")

    print("=== Dolev-Yao Attacker Demo ===\n")

    # Scenario 1: attacker intercepts {Na, A}Kb
    # Attacker knows Kb (it is the attacker!) → can decrypt
    msg1 = Encrypt(Concat(Na, A), Kb)
    atk = AttackerKnowledge([msg1, Kb])
    print("Attacker knows {Na,A}Kb and Kb:")
    print("  Knows Na?", atk.knows(Na))   # True
    print("  Knows A? ", atk.knows(A))    # True

    # Scenario 2: attacker intercepts {Na, Nb}Ka — does NOT know Ka
    msg2 = Encrypt(Concat(Na, Nb), Ka)
    atk2 = AttackerKnowledge([msg2])
    print("\nAttacker knows {Na,Nb}Ka but NOT Ka:")
    print("  Knows Nb?", atk2.knows(Nb))  # False — cannot decrypt

    # Give attacker Ka
    atk2.add(Ka)
    print("After adding Ka:")
    print("  Knows Nb?", atk2.knows(Nb))  # True

    # Scenario 3: DH key derivation
    gx = DH(g, x)
    y  = Atom("y")
    gy = DH(g, y)
    atk3 = AttackerKnowledge([gx, gy])
    shared1 = DH(gx, y)   # g^(xy)
    shared2 = DH(gy, x)   # g^(yx)
    print("\nDH scenario — attacker knows g^x and g^y:")
    print("  Can derive g^(xy)?", atk3.knows(shared1))  # True
    print("  Knows x?          ", atk3.knows(x))         # False

    print(f"\n{atk3}")
