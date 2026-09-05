"""
engine/unifier.py
=================
Term pattern matching and unification for QuantumScyther AI.

The engine uses TWO operations:

1. match(pattern, term, env) — one-directional matching.
   Given a PATTERN (containing Variables) and a concrete TERM,
   find a substitution env that makes pattern equal to term.
   Used when a session expects to RECEIVE a message: we match
   the expected pattern against what the attacker delivers.

2. substitute(term, env) — apply a variable binding.
   Replace every Variable in term with its bound value from env.

Variables
---------
A Variable("x") is a placeholder in a pattern.
Conventions used in protocol models:
  Variable("Na_var")  — a freshly generated nonce (will be bound on first use)
  Variable("K_var")   — a key placeholder

Example — NSPK initiator step 2 (expects {Na, Nb}Ka):
    pattern = Encrypt(Concat(Variable("Na"), Variable("Nb")), Atom("Ka"))
    concrete = Encrypt(Concat(Atom("Na"), Atom("Nb_fresh")), Atom("Ka"))
    env = match(pattern, concrete)
    # env = {"Na": Atom("Na"), "Nb": Atom("Nb_fresh")}
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional

from engine.terms import (
    Atom, Concat, DH, Encrypt, Hash, Pair, Term, dh_equal
)


# ── Variable term ─────────────────────────────────────────────────────────────

@dataclass(frozen=True, eq=True)
class Variable(Term):
    """
    A pattern variable — matches any term during unification.

    Variables appear ONLY in protocol role step patterns.
    They are NEVER used as concrete values in the attacker's
    knowledge set.

    name : str — variable name, e.g. "Na", "Nb", "K_session"
    """
    name: str

    def subterms(self) -> FrozenSet[Term]:
        return frozenset({self})

    def __repr__(self) -> str:
        return f"Var({self.name})"

    def __str__(self) -> str:
        return f"?{self.name}"


# ── Substitution environment ──────────────────────────────────────────────────

Env = Dict[str, Term]   # variable name → concrete Term


def substitute(term: Term, env: Env) -> Term:
    """
    Apply substitution env to term — replace every Variable
    with its binding from env.  Returns a new term (no mutation).

    Example:
        substitute(Concat(Variable("Na"), Atom("A")), {"Na": Atom("Na1")})
        → Concat(Atom("Na1"), Atom("A"))
    """
    if isinstance(term, Variable):
        return env.get(term.name, term)
    if isinstance(term, Atom):
        return term
    if isinstance(term, Encrypt):
        return Encrypt(substitute(term.payload, env), substitute(term.key, env))
    if isinstance(term, Concat):
        return Concat(substitute(term.left, env), substitute(term.right, env))
    if isinstance(term, Pair):
        return Pair(substitute(term.first, env), substitute(term.second, env))
    if isinstance(term, Hash):
        return Hash(substitute(term.content, env))
    if isinstance(term, DH):
        return DH(substitute(term.base, env), substitute(term.exponent, env))
    return term


def match(pattern: Term, term: Term, env: Optional[Env] = None) -> Optional[Env]:
    """
    One-directional pattern matching.

    Tries to find a substitution env such that substitute(pattern, env) == term.
    Variables in `pattern` are bound; `term` must be concrete.

    Parameters
    ----------
    pattern : Term — may contain Variable nodes
    term    : Term — fully concrete term (no Variables)
    env     : Env  — existing bindings (extended in place; pass None to start fresh)

    Returns
    -------
    Env if matching succeeds, None if it fails.
    The returned Env is a NEW dict (original env is not mutated).
    """
    if env is None:
        env = {}
    else:
        env = dict(env)  # copy so we don't mutate caller's env

    return _match(pattern, term, env)


def _match(pattern: Term, term: Term, env: Env) -> Optional[Env]:
    # Variable — bind or check consistency
    if isinstance(pattern, Variable):
        if pattern.name in env:
            # Already bound — check the term matches the binding
            existing = env[pattern.name]
            if existing == term or dh_equal(existing, term):
                return env
            return None
        else:
            env[pattern.name] = term
            return env

    # Both atoms — must be equal
    if isinstance(pattern, Atom) and isinstance(term, Atom):
        return env if pattern == term else None

    # Type must match for structured terms
    if type(pattern) != type(term):
        # Allow DH equational equality
        if dh_equal(pattern, term):
            return env
        return None

    if isinstance(pattern, Encrypt) and isinstance(term, Encrypt):
        env = _match(pattern.key, term.key, env)
        if env is None:
            return None
        return _match(pattern.payload, term.payload, env)

    if isinstance(pattern, Concat) and isinstance(term, Concat):
        env = _match(pattern.left, term.left, env)
        if env is None:
            return None
        return _match(pattern.right, term.right, env)

    if isinstance(pattern, Pair) and isinstance(term, Pair):
        env = _match(pattern.first, term.first, env)
        if env is None:
            return None
        return _match(pattern.second, term.second, env)

    if isinstance(pattern, Hash) and isinstance(term, Hash):
        return _match(pattern.content, term.content, env)

    if isinstance(pattern, DH) and isinstance(term, DH):
        env2 = _match(pattern.base, term.base, dict(env))
        if env2 is not None:
            return _match(pattern.exponent, term.exponent, env2)
        # Try DH commutativity
        if dh_equal(pattern, term):
            return env
        return None

    # Structural equality fallback
    return env if pattern == term else None


def free_variables(term: Term) -> FrozenSet[str]:
    """Return the set of variable names appearing in term."""
    if isinstance(term, Variable):
        return frozenset({term.name})
    if isinstance(term, Atom):
        return frozenset()
    if isinstance(term, Encrypt):
        return free_variables(term.payload) | free_variables(term.key)
    if isinstance(term, Concat):
        return free_variables(term.left) | free_variables(term.right)
    if isinstance(term, Pair):
        return free_variables(term.first) | free_variables(term.second)
    if isinstance(term, Hash):
        return free_variables(term.content)
    if isinstance(term, DH):
        return free_variables(term.base) | free_variables(term.exponent)
    return frozenset()


# ── Standalone demo ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    from engine.terms import Atom, Encrypt, Concat

    Na = Atom("Na");  Nb = Atom("Nb_fresh")
    Ka = Atom("Ka");  Kb = Atom("Kb")
    A  = Atom("A")

    # Pattern: {?Na, ?Nb}Ka
    pattern = Encrypt(Concat(Variable("Na"), Variable("Nb")), Ka)
    # Concrete: {Na, Nb_fresh}Ka
    concrete = Encrypt(Concat(Na, Nb), Ka)

    env = match(pattern, concrete)
    print("Pattern :", pattern)
    print("Concrete:", concrete)
    print("Match env:", env)
    # Expected: {"Na": Atom("Na"), "Nb": Atom("Nb_fresh")}

    # Apply substitution
    result = substitute(pattern, env)
    print("After sub:", result)
    print("Equal to concrete:", result == concrete)

    # Failed match — wrong key
    env2 = match(pattern, Encrypt(Concat(Na, Nb), Kb))
    print("\nWrong key match:", env2)  # None
