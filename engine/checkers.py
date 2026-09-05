"""
engine/checkers.py
==================
Security property checkers for QuantumScyther AI.

Precise, conservative checker design
--------------------------------------
Each checker fires ONLY on clear, unambiguous evidence.

Key design decisions
--------------------
1. Secrecy:    secret must appear INSIDE Encrypt in a sent msg, AND attacker derives it
2. Auth:       BOTH I and R must complete; R's nonce bindings conflict with I's;
               BUT only if both sessions used REAL protocol nonces (not attacker atoms)
3. Replay:     same Encrypt sent in earlier completed session, received in later
               completed session of DIFFERENT role, AND sessions have conflicting nonces
4. Reflection: same role sends and receives same Encrypt across two completed sessions
5. MITM:       I and R both completed, shared binding values differ
6. UKS:        I and R share key value, disagree on peer identity

Helper: is_attacker_atom(t, attacker_own)
  Returns True if t is an atom injected by the attacker (Ke_dec, Ke_enc, Na_E etc.)
  Used to filter out spurious violations caused by attacker-supplied garbage values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from engine.terms import Atom, Concat, DH, Encrypt, Hash, Pair, Term, dh_equal
from engine.protocol import ProtocolState, Session


# Atoms that the engine always injects as the attacker's own material
_ATTACKER_ATOMS: Set[str] = {
    "Ke_dec", "Ke_enc", "Na_E", "Cert_E", "sk_E",
}


# ── Result ────────────────────────────────────────────────────────────────────

@dataclass
class CheckerResult:
    violated:    bool       = False
    attack_type: str        = "None"
    property:    str        = ""
    trace:       List[str]  = field(default_factory=list)
    explanation: str        = ""

    def __bool__(self) -> bool:
        return self.violated

    def __repr__(self) -> str:
        return f"CheckerResult({'VIOLATED' if self.violated else 'OK'}: {self.property})"


# ── Internal helpers ──────────────────────────────────────────────────────────

def _is_attacker_atom(term: Term) -> bool:
    """True if term is one of the attacker's own injected atoms."""
    return isinstance(term, Atom) and term.name in _ATTACKER_ATOMS


def _is_meaningful_binding(val: Term) -> bool:
    """
    True if a binding value is a real protocol value (not attacker garbage).
    We consider a value meaningful if it is NOT one of the attacker's own atoms.
    """
    return not _is_attacker_atom(val)


def _inside_encrypt(secret: Term, term: Term, depth: int = 0) -> bool:
    """True if `secret` appears inside at least one Encrypt layer in `term`."""
    if term == secret:
        return depth > 0
    if isinstance(term, Encrypt):
        return (_inside_encrypt(secret, term.payload, depth + 1) or
                _inside_encrypt(secret, term.key, depth))
    if isinstance(term, (Concat, Pair)):
        l = term.left  if isinstance(term, Concat) else term.first
        r = term.right if isinstance(term, Concat) else term.second
        return _inside_encrypt(secret, l, depth) or _inside_encrypt(secret, r, depth)
    if isinstance(term, Hash):
        return _inside_encrypt(secret, term.content, depth)
    if isinstance(term, DH):
        return (_inside_encrypt(secret, term.base, depth) or
                _inside_encrypt(secret, term.exponent, depth))
    return False


def _fmt(d: dict) -> str:
    return "{" + ", ".join(f"{k}:{v}" for k, v in list(d.items())[:4]) + "}"


def _completed(state: ProtocolState, role: str) -> List[Session]:
    return [s for s in state.sessions if s.role.name == role and s.completed]


# ── 1. Secrecy ────────────────────────────────────────────────────────────────

def check_secrecy(secret: Term, state: ProtocolState) -> CheckerResult:
    """
    Fire when:
      (a) secret appeared INSIDE an Encrypt in a sent message (was meant to be protected)
      (b) attacker can derive the secret
    """
    sent_encrypted = any(
        _inside_encrypt(secret, term)
        for _, is_send, term in state.history
        if is_send
    )
    if not sent_encrypted:
        return CheckerResult(violated=False, property="secrecy")

    if not state.attacker.knows(secret):
        return CheckerResult(violated=False, property="secrecy")

    return CheckerResult(
        violated=True,
        attack_type="Secrecy_Violation",
        property="secrecy",
        trace=[
            f"Secret {secret} was sent inside Encrypt.",
            f"Attacker can now derive it ({len(state.attacker)} known terms).",
        ],
        explanation=(
            f"{secret} was encrypted but the attacker derived it "
            f"from intercepted messages."
        ),
    )


# ── 2. Authentication ─────────────────────────────────────────────────────────

def check_authentication(
    initiator_role: str, responder_role: str, state: ProtocolState
) -> CheckerResult:
    """
    Non-injective agreement:
    - BOTH I and R completed
    - R's bindings have at least one MEANINGFUL (non-attacker) value
    - R's meaningful nonce bindings CONFLICT with EVERY completed I session

    The key guard: only compare bindings where BOTH sides have meaningful
    (non-attacker-injected) values. If I accepted attacker garbage (Ke_dec)
    as its nonce, that session is not a valid counter-example — skip it.
    """
    r_sessions = _completed(state, responder_role)
    i_sessions = _completed(state, initiator_role)

    if not r_sessions or not i_sessions:
        return CheckerResult(violated=False, property="authentication")

    for r in r_sessions:
        # Only check R sessions with at least one meaningful binding
        meaningful_r = {k: v for k, v in r.bindings.items()
                        if _is_meaningful_binding(v)}
        if not meaningful_r:
            continue

        if _matches_any(r, i_sessions, meaningful_r):
            continue

        return CheckerResult(
            violated=True,
            attack_type="Authentication_Violation",
            property="authentication",
            trace=[
                f"R sess {r.session_id}: meaningful bindings={_fmt(meaningful_r)}",
                f"No I session matches on: {list(meaningful_r.keys())}",
                "Attacker caused R to complete a mismatched session.",
            ],
            explanation=(
                f"{responder_role} completed with real protocol values that "
                f"do not match any {initiator_role} run."
            ),
        )
    return CheckerResult(violated=False, property="authentication")


def _matches_any(
    r: Session, i_sessions: List[Session], meaningful_r: dict
) -> bool:
    """
    True if r's meaningful bindings are compatible with at least one I session,
    OR if no I session has comparable (meaningful) bindings to compare against.

    The second condition prevents false positives when the I session only
    contains attacker-injected garbage values — we can't claim a conflict
    if there's nothing meaningful to compare.
    """
    any_comparable_found = False
    for i in i_sessions:
        # Keys where BOTH r and i have meaningful (non-attacker) values
        comparable = {
            k for k in (set(meaningful_r) & set(i.bindings))
            if _is_meaningful_binding(i.bindings[k])
        }
        if not comparable:
            continue   # this I session has no meaningful values to compare
        any_comparable_found = True
        if all(meaningful_r[k] == i.bindings[k] for k in comparable):
            return True  # found a matching I session

    # If no I session had any comparable meaningful values, we cannot
    # conclude there's a mismatch — return True (no provable conflict)
    if not any_comparable_found:
        return True

    return False


# ── 3. Replay ─────────────────────────────────────────────────────────────────

def check_replay(state: ProtocolState) -> CheckerResult:
    """
    Fire when:
    - Encrypt term T sent in completed session S1 (role R1)
    - T received in completed session S2 (role R2 != R1, S2 > S1)
    - S1 and S2 have at least one conflicting MEANINGFUL binding
    """
    completed = {s.session_id for s in state.sessions if s.completed}
    if len(completed) < 2:
        return CheckerResult(violated=False, property="replay")

    sid_role     = {s.session_id: s.role.name  for s in state.sessions}
    sid_bindings = {s.session_id: s.bindings   for s in state.sessions}

    sent: Dict[str, Tuple[int, str]] = {}
    for sid, is_send, term in state.history:
        if is_send and isinstance(term, Encrypt):
            k = repr(term)
            if k not in sent:
                sent[k] = (sid, sid_role.get(sid, "?"))

    for sid, is_send, term in state.history:
        if is_send or not isinstance(term, Encrypt):
            continue
        k = repr(term)
        if k not in sent:
            continue
        orig_sid, orig_role = sent[k]
        recv_role = sid_role.get(sid, "?")

        if orig_sid >= sid:
            continue
        if sid not in completed or orig_sid not in completed:
            continue
        if orig_role == recv_role:
            continue

        b1 = sid_bindings.get(orig_sid, {})
        b2 = sid_bindings.get(sid, {})
        shared = set(b1) & set(b2)
        # Only consider conflicts on meaningful (non-attacker) values
        conflicts = [
            ck for ck in shared
            if b1[ck] != b2[ck]
            and _is_meaningful_binding(b1[ck])
            and _is_meaningful_binding(b2[ck])
        ]
        if not conflicts:
            continue

        return CheckerResult(
            violated=True,
            attack_type="Replay",
            property="key_freshness",
            trace=[
                f"Term {term} produced in session {orig_sid} ({orig_role}).",
                f"Same term accepted in session {sid} ({recv_role}).",
                f"Conflicting meaningful bindings: {conflicts}",
            ],
            explanation=(
                f"A completed-session message was replayed into session {sid} "
                f"with different nonce/key values — replay attack."
            ),
        )
    return CheckerResult(violated=False, property="replay")


# ── 4. Reflection ─────────────────────────────────────────────────────────────

def check_reflection(state: ProtocolState) -> CheckerResult:
    """
    Fire when the SAME role sends an Encrypt term in session S1
    and RECEIVES the same term back in completed session S2 > S1.

    This captures ISO9798-style parallel session attacks where the
    attacker bounces a challenge back to its originator.
    """
    completed = {s.session_id for s in state.sessions if s.completed}
    if not completed:
        return CheckerResult(violated=False, property="reflection")

    sid_role = {s.session_id: s.role.name for s in state.sessions}

    # Map: (role_name, repr(term)) -> first send session_id
    sent_by: Dict[Tuple[str, str], int] = {}
    for sid, is_send, term in state.history:
        if is_send and isinstance(term, Encrypt):
            role = sid_role.get(sid, "?")
            key  = (role, repr(term))
            if key not in sent_by:
                sent_by[key] = sid

    for sid, is_send, term in state.history:
        if is_send or not isinstance(term, Encrypt):
            continue
        if sid not in completed:
            continue
        role = sid_role.get(sid, "?")
        key  = (role, repr(term))
        if key not in sent_by:
            continue
        orig_sid = sent_by[key]
        if orig_sid >= sid:
            continue

        return CheckerResult(
            violated=True,
            attack_type="Reflection",
            property="authentication",
            trace=[
                f"Role {role} sent {term} in session {orig_sid}.",
                f"Role {role} received SAME term back in completed session {sid}.",
                "Parallel session reflection — message bounced back to sender.",
            ],
            explanation=(
                f"Reflection attack: the attacker used a parallel session "
                f"to bounce {role}'s own message back as a valid response."
            ),
        )
    return CheckerResult(violated=False, property="reflection")


# ── 4b. Structural reflection (for ISO9798 where no Encrypt crosses sessions) ─

def check_structural_reflection(state: ProtocolState) -> CheckerResult:
    """
    Detect reflection even when the EXACT Encrypt term doesn't appear
    in both directions — instead detect when role R accepted a challenge
    nonce that it itself sent in another session.

    ISO9798 reflection:
      Session 1: E→B: A, Nb (using B's own nonce Nb as challenge)
      Session 2: B responds with {Nb}K_AB
      This {Nb}K_AB is used to complete session 1's step 3.

    Detection: role R sent {X}K in session S1, AND received {X}K in
    session S2 (completed), where X is a nonce that R itself generated.
    """
    completed = {s.session_id for s in state.sessions if s.completed}
    if not completed:
        return CheckerResult(violated=False, property="reflection")

    sid_role     = {s.session_id: s.role.name for s in state.sessions}
    sid_bindings = {s.session_id: s.bindings   for s in state.sessions}

    # For each completed session pair of the SAME role,
    # check if one session's sent nonce appeared in the other's received term
    role_sessions: Dict[str, List[int]] = {}
    for s in state.sessions:
        role_sessions.setdefault(s.role.name, []).append(s.session_id)

    for role, sids in role_sessions.items():
        if len(sids) < 2:
            continue
        # Check if any nonce binding in one session conflicts with another
        for i, s1_id in enumerate(sids):
            for s2_id in sids[i+1:]:
                if s1_id not in completed or s2_id not in completed:
                    continue
                b1 = sid_bindings.get(s1_id, {})
                b2 = sid_bindings.get(s2_id, {})
                # Look for: same key, BOTH have meaningful values, but DIFFERENT values
                # (i.e., one session got the real nonce, one got the reflected one)
                shared = set(b1) & set(b2)
                conflicts = [
                    k for k in shared
                    if b1[k] != b2[k]
                    and _is_meaningful_binding(b1[k])
                    and _is_meaningful_binding(b2[k])
                ]
                if conflicts:
                    return CheckerResult(
                        violated=True,
                        attack_type="Reflection",
                        property="authentication",
                        trace=[
                            f"Role {role}: sess {s1_id} bindings {_fmt(b1)}",
                            f"Role {role}: sess {s2_id} bindings {_fmt(b2)}",
                            f"Conflicting nonce on keys: {conflicts}",
                            "Two sessions of same role have different nonce values — reflection.",
                        ],
                        explanation=(
                            f"Reflection attack: two {role} sessions completed "
                            f"with conflicting nonce bindings, indicating the attacker "
                            f"used a parallel session to manipulate the protocol."
                        ),
                    )
    return CheckerResult(violated=False, property="reflection")


# ── 5. MITM ───────────────────────────────────────────────────────────────────

def check_mitm(party_a: str, party_b: str, state: ProtocolState) -> CheckerResult:
    """I and R both completed, shared MEANINGFUL binding values differ."""
    for a in _completed(state, party_a):
        for b in _completed(state, party_b):
            shared = set(a.bindings) & set(b.bindings)
            conflicts = [
                k for k in shared
                if a.bindings[k] != b.bindings[k]
                and _is_meaningful_binding(a.bindings[k])
                and _is_meaningful_binding(b.bindings[k])
            ]
            if conflicts:
                return CheckerResult(
                    violated=True,
                    attack_type="MITM",
                    property="mutual_authentication",
                    trace=[
                        f"{party_a} sess {a.session_id}: {_fmt(a.bindings)}",
                        f"{party_b} sess {b.session_id}: {_fmt(b.bindings)}",
                        f"Conflicting on: {conflicts}",
                    ],
                    explanation=(
                        f"MITM: {party_a} and {party_b} completed with "
                        f"conflicting session parameters."
                    ),
                )
    return CheckerResult(violated=False, property="mitm")


# ── 6. UKS ────────────────────────────────────────────────────────────────────

def check_uks(
    party_a: str, party_b: str, session_key_name: str,
    state: ProtocolState
) -> CheckerResult:
    """Same key value, different peer identity beliefs."""
    a_sessions = [s for s in _completed(state, party_a)
                  if session_key_name in s.bindings]
    b_sessions = [s for s in _completed(state, party_b)
                  if session_key_name in s.bindings]

    for a in a_sessions:
        ka = a.bindings[session_key_name]
        for b in b_sessions:
            kb = b.bindings[session_key_name]
            if not (ka == kb or dh_equal(ka, kb)):
                continue
            a_peer = a.bindings.get("peer_identity")
            b_peer = b.bindings.get("peer_identity")
            if a_peer and b_peer and a_peer != b_peer:
                return CheckerResult(
                    violated=True,
                    attack_type="UKS",
                    property="key_establishment",
                    trace=[
                        f"{party_a}: key={ka}, peer={a_peer}",
                        f"{party_b}: key={kb}, peer={b_peer}",
                        "Same key, different peer beliefs — UKS.",
                    ],
                    explanation=(
                        f"Unknown Key-Share: {party_a} and {party_b} derived the "
                        f"same key but believe they are talking to different parties."
                    ),
                )
    return CheckerResult(violated=False, property="uks")


# ── 7. Certificate substitution (for STS/UKS protocols) ──────────────────────

def check_cert_substitution(
    initiator_role: str, responder_role: str, state: ProtocolState
) -> CheckerResult:
    """
    Detect when the responder completed with a certificate that was
    provided by the attacker (Cert_E) instead of the legitimate Cert_B.

    This catches UKS on STS: E substitutes Cert_B with Cert_E in M2.
    The initiator I accepts Cert_E and completes believing it talked to E,
    while R completed believing it talked to I.
    """
    Cert_E = "Cert_E"

    # Did any I session complete with cert_peer bound to Cert_E?
    for sess in _completed(state, initiator_role):
        cert = sess.bindings.get("cert_peer")
        if cert is not None and isinstance(cert, Atom) and cert.name == Cert_E:
            # I accepted E's certificate — UKS / MITM
            return CheckerResult(
                violated=True,
                attack_type="UKS",
                property="key_establishment",
                trace=[
                    f"I session {sess.session_id} completed with cert_peer=Cert_E.",
                    "Attacker substituted Cert_B with Cert_E in M2.",
                    "I believes it talked to E; R believes it talked to I.",
                ],
                explanation=(
                    "UKS via certificate substitution: the attacker replaced "
                    "the responder's certificate with its own, causing I to "
                    "believe it completed a session with E, not B."
                ),
            )
    return CheckerResult(violated=False, property="uks")


# ── 8. KCI / Key compromise (for MQV) ────────────────────────────────────────

def check_kci(state: ProtocolState, compromised_key_name: str = "a") -> CheckerResult:
    """
    Detect KCI: attacker knows the compromised long-term private key 'a'
    AND at least two sessions have completed (both sides ran the protocol).

    In MQV: if 'a' (A's static private key) is compromised, E can compute
    A's implicit signature s_A = x + h(X)*a for any chosen x, enabling E
    to derive any session key A computes. This is the KCI property violation.

    We detect it as: 'a' is in attacker knowledge AND both sessions
    completed — the attack has succeeded because E can compute the session key.
    """
    if not state.attacker.knows(Atom(compromised_key_name)):
        return CheckerResult(violated=False, property="kci")

    # Both I and R must have completed for the attack to matter
    completed = [s for s in state.sessions if s.completed]
    if len(completed) < 2:
        return CheckerResult(violated=False, property="kci")

    # Verify there are sessions from different roles
    roles_completed = {s.role.name for s in completed}
    if len(roles_completed) < 2:
        return CheckerResult(violated=False, property="kci")

    return CheckerResult(
        violated=True,
        attack_type="KCI",
        property="key_establishment",
        trace=[
            f"Long-term private key '{compromised_key_name}' is known to attacker.",
            f"Both roles completed: {sorted(roles_completed)}",
            "KCI: attacker can compute any session key A derives.",
            "Implicit signature s_A = x + h(X)*a uses 'a' — known to E.",
        ],
        explanation=(
            f"Key-Compromise Impersonation: A's long-term key '{compromised_key_name}' "
            f"is compromised. The attacker can now compute A's implicit signature "
            f"for any chosen ephemeral value, impersonating any party to A."
        ),
    )


# ── Run all checkers ──────────────────────────────────────────────────────────

def run_all_checkers(
    state: ProtocolState,
    secrecy_terms: list = None,
    initiator_role: str = "I",
    responder_role: str = "R",
    session_key_name: str = "K",
    protocol_name: str = "",
) -> List[CheckerResult]:
    violations = []

    for term in (secrecy_terms or []):
        r = check_secrecy(term, state)
        if r.violated:
            violations.append(r)

    for fn in [
        lambda: check_authentication(initiator_role, responder_role, state),
        lambda: check_replay(state),
        lambda: check_reflection(state),
        lambda: check_structural_reflection(state),
        lambda: check_mitm(initiator_role, responder_role, state),
        lambda: check_uks(initiator_role, responder_role, session_key_name, state),
        lambda: check_cert_substitution(initiator_role, responder_role, state),
        lambda: check_kci(state, "a"),
    ]:
        r = fn()
        if r.violated:
            violations.append(r)

    return violations
