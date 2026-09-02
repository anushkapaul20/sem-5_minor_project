"""
engine/checkers.py
==================
Security property checkers for QuantumScyther AI.

Each checker receives a ProtocolState and returns a CheckerResult
indicating whether the property is violated and, if so, providing
the attack trace.

Six checkers
------------
check_secrecy        — Is a secret term derivable by the attacker?
check_authentication — Does a completed responder run have a matching initiator run?
check_replay         — Is any message accepted that was sent in a prior session?
check_reflection     — Is any message reflected back to its sender?
check_mitm           — Can the attacker complete sessions with both A and B?
check_uks            — Do parties agree on the key but disagree on partner identity?

Usage
-----
    from engine.checkers import check_secrecy, CheckerResult
    result = check_secrecy(Na, state)
    if result.violated:
        print("ATTACK:", result.attack_type)
        print("Trace :", result.trace)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from engine.terms import Atom, Encrypt, Term, dh_equal
from engine.protocol import ProtocolState, Session, Message


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class CheckerResult:
    """
    Result of running one property checker against a ProtocolState.

    Parameters
    ----------
    violated     : True if the property is violated (attack found)
    attack_type  : controlled vocabulary label (e.g. "MITM", "Replay")
    property     : name of the security property checked
    trace        : ordered list of strings describing the attack trace
    explanation  : one-sentence summary of what went wrong
    """
    violated:    bool        = False
    attack_type: str         = "None"
    property:    str         = ""
    trace:       List[str]   = field(default_factory=list)
    explanation: str         = ""

    def __bool__(self) -> bool:
        return self.violated

    def __repr__(self) -> str:
        status = "VIOLATED" if self.violated else "OK"
        return f"CheckerResult({self.property}: {status})"


# ── 1. Secrecy Checker ─────────────────────────────────────────────────────────

def check_secrecy(secret: Term, state: ProtocolState) -> CheckerResult:
    """
    Check whether `secret` is derivable by the attacker in `state`.

    Violation: attacker.knows(secret) == True

    Parameters
    ----------
    secret : Term — the value that should remain secret
    state  : ProtocolState — current execution state

    Returns
    -------
    CheckerResult
    """
    if state.attacker.knows(secret):
        return CheckerResult(
            violated=True,
            attack_type="Secrecy_Violation",
            property="secrecy",
            trace=[
                f"Secret term {secret} is derivable by the attacker.",
                f"Attacker knowledge contains {len(state.attacker)} terms.",
            ],
            explanation=(
                f"The term {secret} which should be secret is derivable "
                f"by the Dolev-Yao attacker from intercepted messages."
            ),
        )
    return CheckerResult(violated=False, property="secrecy")


# ── 2. Authentication Checker ──────────────────────────────────────────────────

def check_authentication(
    initiator_role: str,
    responder_role: str,
    state: ProtocolState,
) -> CheckerResult:
    """
    Check non-injective agreement: whenever the responder completes a run,
    there must be a corresponding completed initiator run with the same
    session parameters.

    Violation: a responder session completed but no matching initiator session
    exists with the same binding values.

    Parameters
    ----------
    initiator_role : str — name of the initiator role (e.g. "I")
    responder_role : str — name of the responder role  (e.g. "R")
    state          : ProtocolState

    Returns
    -------
    CheckerResult
    """
    responder_sessions = [
        s for s in state.sessions
        if s.role.name == responder_role and s.completed
    ]
    initiator_sessions = [
        s for s in state.sessions
        if s.role.name == initiator_role and s.completed
    ]

    for r_sess in responder_sessions:
        # Check if there exists a matching initiator session
        match_found = False
        for i_sess in initiator_sessions:
            # Matching means shared bindings agree on common keys
            common_keys = set(r_sess.bindings) & set(i_sess.bindings)
            if all(r_sess.bindings[k] == i_sess.bindings[k] for k in common_keys):
                match_found = True
                break

        if not match_found:
            return CheckerResult(
                violated=True,
                attack_type="Authentication_Violation",
                property="authentication",
                trace=[
                    f"Responder session {r_sess.session_id} completed.",
                    f"No matching initiator session found.",
                    f"Responder bindings: {r_sess.bindings}",
                    f"Completed initiator sessions: {[s.session_id for s in initiator_sessions]}",
                ],
                explanation=(
                    f"The responder ({responder_role}) completed a session "
                    f"but no corresponding initiator ({initiator_role}) run "
                    f"with matching parameters was found — "
                    f"authentication property (non-injective agreement) violated."
                ),
            )

    return CheckerResult(violated=False, property="authentication")


# ── 3. Replay Checker ──────────────────────────────────────────────────────────

def check_replay(state: ProtocolState) -> CheckerResult:
    """
    Check for replay: a message term that was sent in session N is
    accepted (received) in a later session M without modification.

    Violation: the same term appears as a sent message in one session
    and as a received message in another session with a different session_id.

    Parameters
    ----------
    state : ProtocolState

    Returns
    -------
    CheckerResult
    """
    # Build map: term → list of (session_id, direction)
    term_history: dict = {}
    for session_id, msg in state.sent_messages:
        key = repr(msg.term)
        if key not in term_history:
            term_history[key] = []
        term_history[key].append((session_id, "send" if msg.send else "receive", msg))

    for key, occurrences in term_history.items():
        send_sessions    = {s for s, d, _ in occurrences if d == "send"}
        receive_sessions = {s for s, d, _ in occurrences if d == "receive"}
        # Same term sent in one session and received in a DIFFERENT session
        if send_sessions and receive_sessions:
            cross = receive_sessions - send_sessions
            if cross:
                _, _, sample_msg = occurrences[0]
                return CheckerResult(
                    violated=True,
                    attack_type="Replay",
                    property="key_freshness",
                    trace=[
                        f"Term {sample_msg.term} was originally sent in session(s) {send_sessions}.",
                        f"The same term was received in session(s) {cross}.",
                        "This indicates a replay of a previously captured message.",
                    ],
                    explanation=(
                        f"A message term was accepted in a session where it was never "
                        f"freshly generated — it was replayed from a previous session. "
                        f"This violates key freshness / authentication."
                    ),
                )

    return CheckerResult(violated=False, property="replay")


# ── 4. Reflection Checker ──────────────────────────────────────────────────────

def check_reflection(state: ProtocolState) -> CheckerResult:
    """
    Check for reflection: a message is sent back to the party who originally
    sent it, without the receiver knowing it is their own message.

    Violation: a term sent by party X is received by party X in a different
    session (or different step), creating a closed loop.

    Parameters
    ----------
    state : ProtocolState

    Returns
    -------
    CheckerResult
    """
    # Group sent messages by (sender, term)
    sent_by: dict = {}
    for session_id, msg in state.sent_messages:
        if msg.send:
            key = (msg.sender, repr(msg.term))
            sent_by[key] = (session_id, msg)

    # Check for reflection: party X receives its own term
    for session_id, msg in state.sent_messages:
        if not msg.send:  # received message
            key = (msg.receiver, repr(msg.term))
            if key in sent_by:
                orig_session, orig_msg = sent_by[key]
                if orig_session != session_id:  # different session = reflection
                    return CheckerResult(
                        violated=True,
                        attack_type="Reflection",
                        property="authentication",
                        trace=[
                            f"{msg.receiver} originally sent {msg.term} in session {orig_session}.",
                            f"{msg.receiver} received the same term in session {session_id}.",
                            "This is a reflection — the message was sent back to its originator.",
                        ],
                        explanation=(
                            f"A message was reflected back to {msg.receiver} who originally "
                            f"sent it. The attacker exploited the symmetric key structure to "
                            f"use the sender's own challenge response against them."
                        ),
                    )

    return CheckerResult(violated=False, property="reflection")


# ── 5. MITM Checker ────────────────────────────────────────────────────────────

def check_mitm(
    party_a: str,
    party_b: str,
    state: ProtocolState,
) -> CheckerResult:
    """
    Check for a Man-in-the-Middle attack: the attacker has completed
    separate sessions with both A and B simultaneously, with A believing
    it talks to B and B believing it talks to A.

    Violation: A completed a session apparently with B, AND B completed
    a session apparently with A, but the session parameters differ (the
    attacker interleaved them).

    Parameters
    ----------
    party_a : str — role name (e.g. "I")
    party_b : str — role name (e.g. "R")
    state   : ProtocolState

    Returns
    -------
    CheckerResult
    """
    a_sessions = [
        s for s in state.sessions
        if s.role.name == party_a and s.completed
    ]
    b_sessions = [
        s for s in state.sessions
        if s.role.name == party_b and s.completed
    ]

    # MITM exists if A and B both completed but their session bindings conflict
    for a_sess in a_sessions:
        for b_sess in b_sessions:
            common = set(a_sess.bindings) & set(b_sess.bindings)
            conflicts = [
                k for k in common
                if a_sess.bindings[k] != b_sess.bindings[k]
            ]
            if conflicts:
                return CheckerResult(
                    violated=True,
                    attack_type="MITM",
                    property="mutual_authentication",
                    trace=[
                        f"{party_a} (session {a_sess.session_id}) completed, believes peer is {party_b}.",
                        f"{party_b} (session {b_sess.session_id}) completed, believes peer is {party_a}.",
                        f"Conflicting bindings on: {conflicts}",
                        "The attacker interleaved both sessions — classic MITM.",
                    ],
                    explanation=(
                        f"A Man-in-the-Middle attack succeeded. {party_a} believes it completed "
                        f"a session with {party_b}, and {party_b} believes it completed a session "
                        f"with {party_a}, but their session parameters conflict — the attacker "
                        f"sat between them and relayed messages in both directions."
                    ),
                )

    return CheckerResult(violated=False, property="mitm")


# ── 6. UKS Checker ────────────────────────────────────────────────────────────

def check_uks(
    party_a: str,
    party_b: str,
    session_key_name: str,
    state: ProtocolState,
) -> CheckerResult:
    """
    Check for Unknown Key Share: A and B agree on the same key value
    but disagree on who they think their partner is.

    Violation: both A and B completed sessions and computed the same
    session key, but A thinks its partner is E while B thinks its
    partner is A.

    Parameters
    ----------
    party_a          : str — initiator role name
    party_b          : str — responder role name
    session_key_name : str — binding name for the session key (e.g. "K")
    state            : ProtocolState

    Returns
    -------
    CheckerResult
    """
    a_sessions = [
        s for s in state.sessions
        if s.role.name == party_a and s.completed
        and session_key_name in s.bindings
    ]
    b_sessions = [
        s for s in state.sessions
        if s.role.name == party_b and s.completed
        and session_key_name in s.bindings
    ]

    for a_sess in a_sessions:
        ka = a_sess.bindings[session_key_name]
        for b_sess in b_sessions:
            kb = b_sess.bindings[session_key_name]
            # Same key (structurally or via DH axiom)
            if dh_equal(ka, kb) or ka == kb:
                # Check if identity bindings disagree
                a_peer = a_sess.bindings.get("peer_identity")
                b_peer = b_sess.bindings.get("peer_identity")
                if a_peer and b_peer and a_peer != b_peer:
                    return CheckerResult(
                        violated=True,
                        attack_type="UKS",
                        property="key_establishment",
                        trace=[
                            f"{party_a} (session {a_sess.session_id}) computed key {ka}.",
                            f"{party_b} (session {b_sess.session_id}) computed key {kb}.",
                            f"Keys are equal: {ka} == {kb}",
                            f"{party_a} believes peer is {a_peer}.",
                            f"{party_b} believes peer is {b_peer}.",
                            "Parties share a key but disagree on partner identity — UKS.",
                        ],
                        explanation=(
                            f"Unknown Key-Share attack: {party_a} and {party_b} computed "
                            f"the same session key but hold different beliefs about their "
                            f"partner's identity. The key value is not compromised, but "
                            f"the identity binding is wrong."
                        ),
                    )

    return CheckerResult(violated=False, property="uks")


# ── Run all checkers ───────────────────────────────────────────────────────────

def run_all_checkers(
    state: ProtocolState,
    secrecy_terms: list = None,
    initiator_role: str = "I",
    responder_role: str = "R",
    session_key_name: str = "K",
) -> List[CheckerResult]:
    """
    Run all six property checkers on a given state.
    Returns list of violated CheckerResults (only violations, not OK results).

    Parameters
    ----------
    state            : ProtocolState — final or intermediate engine state
    secrecy_terms    : list of Term objects that should remain secret
    initiator_role   : str
    responder_role   : str
    session_key_name : str — binding name for session key in UKS check
    """
    violations = []

    # Secrecy
    for term in (secrecy_terms or []):
        r = check_secrecy(term, state)
        if r.violated:
            violations.append(r)

    # Authentication
    r = check_authentication(initiator_role, responder_role, state)
    if r.violated:
        violations.append(r)

    # Replay
    r = check_replay(state)
    if r.violated:
        violations.append(r)

    # Reflection
    r = check_reflection(state)
    if r.violated:
        violations.append(r)

    # MITM
    r = check_mitm(initiator_role, responder_role, state)
    if r.violated:
        violations.append(r)

    # UKS
    r = check_uks(initiator_role, responder_role, session_key_name, state)
    if r.violated:
        violations.append(r)

    return violations
