"""
tests/test_checkers.py
======================
Unit tests for engine/checkers.py — all 6 property checkers.

Tests use minimal hand-crafted ProtocolState objects — fast and deterministic.
Each test is aligned to the ACTUAL checker contracts:

  check_secrecy  — fires only when secret was INSIDE an Encrypt in a sent message
                   AND attacker can now derive it
  check_auth     — fires only when BOTH I and R completed AND their bindings conflict
  check_replay   — fires only when BOTH sessions completed, different roles,
                   and an Encrypt term was sent in an earlier session and received
                   in a later one
  check_reflection — fires only when the same role sends and receives the same
                     Encrypt term across two completed sessions
  check_mitm     — fires when I and R both completed with conflicting bindings
  check_uks      — fires when I and R share a key value but differ on peer_identity
"""
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.terms import Atom, Concat, Encrypt, DH
from engine.dolev_yao import AttackerKnowledge
from engine.protocol import Message, ProtocolState, Role, Session
from engine.checkers import (
    CheckerResult,
    check_secrecy,
    check_authentication,
    check_replay,
    check_reflection,
    check_mitm,
    check_uks,
    run_all_checkers,
)


# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════

def _role(name: str) -> Role:
    return Role(name, steps=[])


def _done(sid: int, role_name: str, bindings: dict = None) -> Session:
    """Return a completed Session with the given bindings."""
    s = Session(session_id=sid, role=_role(role_name), bindings=bindings or {})
    s.completed = True
    return s


def _active(sid: int, role_name: str) -> Session:
    """Return a NOT-completed Session."""
    return Session(session_id=sid, role=_role(role_name))


def _state(*sessions, attacker_knows=None, history=None) -> ProtocolState:
    """
    Build a minimal ProtocolState.
    history items: (session_id, is_send: bool, term)
    """
    atk = AttackerKnowledge(attacker_knows or [])
    ps  = ProtocolState(sessions=list(sessions), attacker=atk)
    ps.history = list(history or [])
    return ps


def _send(sid: int, term) -> tuple:
    return (sid, True, term)


def _recv(sid: int, term) -> tuple:
    return (sid, False, term)


# ══════════════════════════════════════════════════════════════════
# CheckerResult
# ══════════════════════════════════════════════════════════════════

def test_checker_result_bool_true():
    assert bool(CheckerResult(violated=True))

def test_checker_result_bool_false():
    assert not bool(CheckerResult(violated=False))

def test_checker_result_repr_violated():
    assert "VIOLATED" in repr(CheckerResult(violated=True, property="secrecy"))

def test_checker_result_repr_ok():
    assert "OK" in repr(CheckerResult(violated=False, property="secrecy"))


# ══════════════════════════════════════════════════════════════════
# check_secrecy
# ══════════════════════════════════════════════════════════════════
# Contract: fires when secret is INSIDE an Encrypt in a sent message
# AND attacker can derive secret.
# Does NOT fire if secret was sent in plaintext (not protected = not secret).

def test_secrecy_violated_encrypted_and_attacker_knows():
    """Secret sent inside Encrypt, attacker has decryption key → violation."""
    Na, Kb = Atom("Na"), Atom("Kb")
    msg = Encrypt(Na, Kb)
    # Attacker knows Kb → can decrypt → knows Na
    state = _state(
        _done(0, "I"),
        attacker_knows=[msg, Kb],
        history=[_send(0, msg)],
    )
    r = check_secrecy(Na, state)
    assert r.violated
    assert r.attack_type == "Secrecy_Violation"


def test_secrecy_ok_attacker_cannot_decrypt():
    """Secret inside Encrypt, attacker does NOT have the key."""
    Na, Kb = Atom("Na"), Atom("Kb")
    msg = Encrypt(Na, Kb)
    state = _state(
        _done(0, "I"),
        attacker_knows=[msg],       # no Kb
        history=[_send(0, msg)],
    )
    assert not check_secrecy(Na, state).violated


def test_secrecy_ok_secret_sent_in_plaintext():
    """
    Secret sent in plaintext is by design public — NOT a secrecy violation.
    (e.g. identity A sent as A, B, Na in NSSK step 1)
    """
    Na = Atom("Na")
    state = _state(
        _done(0, "I"),
        attacker_knows=[Na],
        history=[_send(0, Na)],     # plaintext — not inside Encrypt
    )
    assert not check_secrecy(Na, state).violated


def test_secrecy_ok_no_history():
    """No send events → nothing to check."""
    Na = Atom("Na")
    state = _state(attacker_knows=[Na])
    assert not check_secrecy(Na, state).violated


def test_secrecy_ok_inside_concat_inside_encrypt():
    """Secret inside Concat inside Encrypt — attacker knows key → violation."""
    Na, A, Kb = Atom("Na"), Atom("A"), Atom("Kb")
    msg = Encrypt(Concat(Na, A), Kb)
    state = _state(
        _done(0, "I"),
        attacker_knows=[msg, Kb],
        history=[_send(0, msg)],
    )
    assert check_secrecy(Na, state).violated


# ══════════════════════════════════════════════════════════════════
# check_authentication
# ══════════════════════════════════════════════════════════════════
# Contract: fires only when BOTH I AND R completed AND R's bindings
# conflict with every completed I session on shared keys.

def test_auth_ok_matching_bindings():
    """I and R both completed, same nonce value → no violation."""
    bindings = {"Na": Atom("Na"), "Nb": Atom("Nb")}
    state = _state(_done(0, "I", dict(bindings)), _done(1, "R", dict(bindings)))
    assert not check_authentication("I", "R", state).violated


def test_auth_violated_conflicting_nonces():
    """I completed with Na=Na1, R completed with Na=Na2 → CONFLICT → violation."""
    state = _state(
        _done(0, "I", {"Na": Atom("Na1")}),
        _done(1, "R", {"Na": Atom("Na2")}),
    )
    r = check_authentication("I", "R", state)
    assert r.violated
    assert r.attack_type == "Authentication_Violation"


def test_auth_ok_only_responder_completed():
    """Only R completed — no I completed → NEW checker requires both → no violation."""
    state = _state(_done(1, "R", {"Na": Atom("Na")}))
    # New checker: both sides must complete before we can check agreement
    assert not check_authentication("I", "R", state).violated


def test_auth_ok_only_initiator_completed():
    """Only I completed → no violation."""
    state = _state(_done(0, "I", {"Na": Atom("Na")}))
    assert not check_authentication("I", "R", state).violated


def test_auth_ok_no_sessions():
    """No sessions → no violation."""
    assert not check_authentication("I", "R", _state()).violated


def test_auth_ok_empty_bindings():
    """Both completed but empty bindings → nothing to conflict on → no violation."""
    state = _state(_done(0, "I", {}), _done(1, "R", {}))
    assert not check_authentication("I", "R", state).violated


def test_auth_ok_no_shared_keys():
    """I has {Na:x}, R has {Nb:y} — no overlap → no conflict → no violation."""
    state = _state(
        _done(0, "I", {"Na": Atom("Na1")}),
        _done(1, "R", {"Nb": Atom("Nb1")}),
    )
    assert not check_authentication("I", "R", state).violated


# ══════════════════════════════════════════════════════════════════
# check_replay
# ══════════════════════════════════════════════════════════════════
# Contract: fires when an Encrypt term sent in an earlier COMPLETED
# session is received in a later COMPLETED session of a DIFFERENT role.

def test_replay_detected():
    """Encrypt term sent in sess 0 (I, completed), received in sess 1 (R, completed)
    AND sessions have conflicting bindings → replay."""
    t = Encrypt(Atom("K_AB"), Atom("K_BS"))
    # Different nonce bindings — proves attacker substituted stale message
    i = _done(0, "I", {"Na": Atom("Na_old")})
    r = _done(1, "R", {"Na": Atom("Na_new")})
    state = _state(i, r, history=[_send(0, t), _recv(1, t)])
    result = check_replay(state)
    assert result.violated
    assert result.attack_type == "Replay"


def test_replay_ok_same_session():
    """Send and receive in the same session — not a replay."""
    t = Encrypt(Atom("K"), Atom("K2"))
    s = _done(0, "I")
    state = _state(s, history=[_send(0, t), _recv(0, t)])
    assert not check_replay(state).violated


def test_replay_ok_different_terms():
    t1 = Encrypt(Atom("K1"), Atom("Kb"))
    t2 = Encrypt(Atom("K2"), Atom("Kb"))
    state = _state(
        _done(0, "I"), _done(1, "R"),
        history=[_send(0, t1), _recv(1, t2)],
    )
    assert not check_replay(state).violated


def test_replay_ok_only_atoms():
    """Atom terms (not Encrypt) — not flagged as replay."""
    t = Atom("Na")
    state = _state(
        _done(0, "I"), _done(1, "R"),
        history=[_send(0, t), _recv(1, t)],
    )
    assert not check_replay(state).violated


def test_replay_ok_receiving_session_not_completed():
    """Receiving session did not complete → replay not accepted → no violation."""
    t = Encrypt(Atom("K"), Atom("Kb"))
    state = _state(
        _done(0, "I"),
        _active(1, "R"),           # NOT completed
        history=[_send(0, t), _recv(1, t)],
    )
    assert not check_replay(state).violated


def test_replay_ok_same_role():
    """Same role sending and receiving → not a cross-session replay."""
    t = Encrypt(Atom("K"), Atom("Kb"))
    state = _state(
        _done(0, "I"), _done(1, "I"),   # both same role "I"
        history=[_send(0, t), _recv(1, t)],
    )
    assert not check_replay(state).violated


def test_replay_ok_no_history():
    assert not check_replay(_state()).violated


# ══════════════════════════════════════════════════════════════════
# check_reflection
# ══════════════════════════════════════════════════════════════════
# Contract: fires when the same role sends an Encrypt term in session S1
# and receives the same term in a later COMPLETED session S2.

def test_reflection_detected():
    """Role I sent Encrypt t in sess 0, received t in completed sess 1."""
    t = Encrypt(Atom("Na"), Atom("K_AB"))
    state = _state(
        _done(0, "I"), _done(1, "I"),
        history=[_send(0, t), _recv(1, t)],
    )
    r = check_reflection(state)
    assert r.violated
    assert r.attack_type == "Reflection"


def test_reflection_ok_different_roles():
    """I sends, R receives — different roles, not a reflection."""
    t = Encrypt(Atom("Na"), Atom("K_AB"))
    state = _state(
        _done(0, "I"), _done(1, "R"),
        history=[_send(0, t), _recv(1, t)],
    )
    assert not check_reflection(state).violated


def test_reflection_ok_same_session():
    """Send and receive in the same session — not a reflection."""
    t = Encrypt(Atom("Na"), Atom("K"))
    state = _state(
        _done(0, "I"),
        history=[_send(0, t), _recv(0, t)],
    )
    assert not check_reflection(state).violated


def test_reflection_ok_receiving_not_completed():
    """Receiving session didn't complete → reflection not accepted."""
    t = Encrypt(Atom("Na"), Atom("K"))
    state = _state(
        _done(0, "I"),
        _active(1, "I"),
        history=[_send(0, t), _recv(1, t)],
    )
    assert not check_reflection(state).violated


def test_reflection_ok_atoms_only():
    """Plain atoms — not flagged as reflection."""
    t = Atom("Na")
    state = _state(
        _done(0, "I"), _done(1, "I"),
        history=[_send(0, t), _recv(1, t)],
    )
    assert not check_reflection(state).violated


def test_reflection_ok_no_history():
    assert not check_reflection(_state()).violated


# ══════════════════════════════════════════════════════════════════
# check_mitm
# ══════════════════════════════════════════════════════════════════

def test_mitm_detected():
    """I and R both completed, conflicting binding on session_key → MITM."""
    i = _done(0, "I", {"Na": Atom("Na"), "K": Atom("K1")})
    r = _done(1, "R", {"Na": Atom("Na"), "K": Atom("K2")})
    state = _state(i, r)
    result = check_mitm("I", "R", state)
    assert result.violated
    assert result.attack_type == "MITM"


def test_mitm_ok_matching():
    bindings = {"Na": Atom("Na"), "Nb": Atom("Nb")}
    state = _state(_done(0, "I", dict(bindings)), _done(1, "R", dict(bindings)))
    assert not check_mitm("I", "R", state).violated


def test_mitm_ok_no_overlap():
    """No shared binding keys → no conflict."""
    state = _state(
        _done(0, "I", {"Na": Atom("Na")}),
        _done(1, "R", {"Nb": Atom("Nb")}),
    )
    assert not check_mitm("I", "R", state).violated


def test_mitm_ok_empty():
    assert not check_mitm("I", "R", _state()).violated


# ══════════════════════════════════════════════════════════════════
# check_uks
# ══════════════════════════════════════════════════════════════════

def test_uks_detected():
    K = Atom("K_session")
    i = _done(0, "I", {"K_sess": K, "peer_identity": Atom("E")})
    r = _done(1, "R", {"K_sess": K, "peer_identity": Atom("A")})
    state = _state(i, r)
    result = check_uks("I", "R", "K_sess", state)
    assert result.violated
    assert result.attack_type == "UKS"


def test_uks_ok_no_key_binding():
    state = _state(_done(0, "I", {}), _done(1, "R", {}))
    assert not check_uks("I", "R", "K_sess", state).violated


def test_uks_ok_no_sessions():
    assert not check_uks("I", "R", "K_sess", _state()).violated


# ══════════════════════════════════════════════════════════════════
# run_all_checkers
# ══════════════════════════════════════════════════════════════════

def test_run_all_no_violations():
    """Empty state → no violations."""
    assert run_all_checkers(_state()) == []


def test_run_all_finds_secrecy_violation():
    """Attacker decrypts a secret that was sent encrypted → secrecy violation."""
    Na, Kb = Atom("Na"), Atom("Kb")
    msg = Encrypt(Na, Kb)
    state = _state(
        _done(0, "I"),
        attacker_knows=[msg, Kb],
        history=[_send(0, msg)],
    )
    violations = run_all_checkers(state, secrecy_terms=[Na])
    assert any(v.attack_type == "Secrecy_Violation" for v in violations)


def test_run_all_finds_auth_violation():
    """Both I and R completed with conflicting nonces → auth violation."""
    state = _state(
        _done(0, "I", {"Na": Atom("Na1")}),
        _done(1, "R", {"Na": Atom("Na2")}),
    )
    violations = run_all_checkers(state, initiator_role="I", responder_role="R")
    assert any(v.attack_type == "Authentication_Violation" for v in violations)


def test_run_all_finds_replay():
    """Encrypt term replayed from completed session with conflicting bindings → replay."""
    t = Encrypt(Atom("K"), Atom("Kb"))
    state = _state(
        _done(0, "I", {"Na": Atom("Na_old")}),
        _done(1, "R", {"Na": Atom("Na_new")}),
        history=[_send(0, t), _recv(1, t)],
    )
    violations = run_all_checkers(state)
    assert any(v.attack_type == "Replay" for v in violations)


def test_run_all_finds_reflection():
    """Same role sends and receives same Encrypt → reflection."""
    t = Encrypt(Atom("Na"), Atom("K_AB"))
    state = _state(
        _done(0, "I"), _done(1, "I"),
        history=[_send(0, t), _recv(1, t)],
    )
    violations = run_all_checkers(state)
    assert any(v.attack_type == "Reflection" for v in violations)


def test_run_all_multiple_violations():
    """Secrecy + auth violation simultaneously."""
    Na, Kb = Atom("Na"), Atom("Kb")
    msg = Encrypt(Na, Kb)
    state = _state(
        _done(0, "I", {"Na": Atom("Na1")}),
        _done(1, "R", {"Na": Atom("Na2")}),
        attacker_knows=[msg, Kb],
        history=[_send(0, msg)],
    )
    violations = run_all_checkers(
        state,
        secrecy_terms=[Na],
        initiator_role="I",
        responder_role="R",
    )
    types = {v.attack_type for v in violations}
    assert "Secrecy_Violation" in types
    assert "Authentication_Violation" in types


def test_run_all_mitm_detected():
    i = _done(0, "I", {"Na": Atom("Na"), "K": Atom("K1")})
    r = _done(1, "R", {"Na": Atom("Na"), "K": Atom("K2")})
    violations = run_all_checkers(_state(i, r), initiator_role="I", responder_role="R")
    assert any(v.attack_type == "MITM" for v in violations)
