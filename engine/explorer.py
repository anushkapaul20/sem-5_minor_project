"""
engine/explorer.py
==================
Bounded symbolic BFS model checker for QuantumScyther AI.

Two-pass strategy
-----------------
Pass 1 — Honest run:  execute protocol roles honestly, check properties.
Pass 2 — Attacker BFS: 2 concurrent sessions, attacker can inject terms.

Candidate priority (per receive step):
  1. Honest expected term
  2. Protocol atoms intercepted from plaintext sends (Na, K_AB, ...)
  3. Intercepted Encrypt terms from history
  4. Attacker's own key atoms
  5. Remaining known terms
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set, Tuple

from engine.terms import Atom, Concat, DH, Encrypt, Hash, Pair, Term, dh_equal
from engine.dolev_yao import AttackerKnowledge
from engine.unifier import Variable, match, substitute
from engine.protocol import Message, ProtocolDef, ProtocolState, Role, Session
from engine.checkers import CheckerResult, run_all_checkers

MAX_CANDS = 10
MAX_QUEUE = 30_000

# Atoms that belong to the attacker — not protocol-generated
_ATTACKER_OWN: Set[str] = {
    "Ke_dec", "Ke_enc", "Na_E", "Cert_E", "sk_E",
}


# ── Result ────────────────────────────────────────────────────────────────────

@dataclass
class VerificationResult:
    attack_found:   bool      = False
    attack_type:    str       = "None"
    property:       str       = ""
    trace:          List[str] = field(default_factory=list)
    explanation:    str       = ""
    states_visited: int       = 0
    time_seconds:   float     = 0.0
    bounded:        bool      = True
    sessions_bound: int       = 2

    def report(self) -> str:
        lines = [
            "",
            "═" * 58,
            "  QuantumScyther AI  —  Verification Result",
            "═" * 58,
        ]
        if self.attack_found:
            lines += [
                "  Result    :  ❌  ATTACK FOUND",
                f"  Attack    :  {self.attack_type}",
                f"  Property  :  {self.property}",
                "",
                "  Attack trace:",
            ]
            for i, line in enumerate(self.trace, 1):
                lines.append(f"    {i:2}. {line}")
            if self.explanation:
                lines += ["", f"  Why: {self.explanation}"]
        else:
            lines.append("  Result    :  ✅  SECURE (within bounded model)")
        lines += [
            "",
            f"  States visited : {self.states_visited}",
            f"  Sessions bound : {self.sessions_bound} per role",
            f"  Time           : {self.time_seconds:.3f}s",
            "  Note: 2-session bounded verifier.",
            "─" * 58,
        ]
        return "\n".join(lines)

    def __repr__(self) -> str:
        s = f"ATTACK({self.attack_type})" if self.attack_found else "SECURE"
        return f"VerificationResult({s}, {self.states_visited} states)"


# ── Internal BFS state ────────────────────────────────────────────────────────

@dataclass
class _State:
    sessions: List[Session]
    attacker: AttackerKnowledge
    # (session_id, is_send, concrete_term)
    history:  List[Tuple[int, bool, Term]]
    trace:    List[str]

    def copy(self) -> "_State":
        return _State(
            sessions=[s.copy() for s in self.sessions],
            attacker=self.attacker.copy(),
            history=list(self.history),
            trace=list(self.trace),
        )

    def key(self) -> str:
        sp = tuple(
            (s.session_id, s.role.name, s.step_index, s.completed,
             tuple(sorted((k, repr(v)) for k, v in s.bindings.items())))
            for s in sorted(self.sessions, key=lambda x: x.session_id)
        )
        # Use only Atom names for attacker key — avoids explosion
        ak = frozenset(
            t.name for t in self.attacker.snapshot()
            if isinstance(t, Atom)
        )
        return repr((sp, ak))

    def to_ps(self) -> ProtocolState:
        ps = ProtocolState(sessions=self.sessions, attacker=self.attacker)
        for sid, is_send, term in self.history:
            ps.sent_messages.append(
                (sid, Message(send=is_send, sender="?",
                              receiver="?", term=term))
            )
        ps.history = list(self.history)
        return ps


# ── Explorer ──────────────────────────────────────────────────────────────────

class Explorer:
    def __init__(
        self,
        max_sessions:    int   = 2,
        depth_limit:     int   = 14,
        timeout_seconds: float = 25.0,
        verbose:         bool  = False,
    ) -> None:
        self.max_sessions    = max_sessions
        self.depth_limit     = depth_limit
        self.timeout_seconds = timeout_seconds
        self.verbose         = verbose

    # ── Public ────────────────────────────────────────────────────────────

    def verify(self, protocol: ProtocolDef) -> VerificationResult:
        t0 = time.time()

        secrecy_terms = [c.term for c in protocol.secrecy_claims]
        init_role     = protocol.roles[0].name if protocol.roles else "I"
        resp_role     = protocol.roles[1].name if len(protocol.roles) > 1 else "R"

        # Pass 1: honest run
        honest_result = self._honest_run(
            protocol, secrecy_terms, init_role, resp_role
        )
        if honest_result is not None:
            return VerificationResult(
                attack_found=True,
                attack_type=honest_result.attack_type,
                property=honest_result.property,
                trace=["[honest run]"] + honest_result.trace,
                explanation=honest_result.explanation,
                states_visited=1,
                time_seconds=time.time() - t0,
                sessions_bound=self.max_sessions,
            )

        # Collect intercepted material from honest run
        honest_material = self._collect_honest_material(protocol)

        # Pass 2: BFS with attacker
        visited: Set[str] = set()
        states_visited    = 0
        initial           = self._initial_state(protocol, honest_material)
        queue: Deque[Tuple[_State, int]] = deque([(initial, 0)])

        while queue:
            if time.time() - t0 > self.timeout_seconds:
                return VerificationResult(
                    attack_found=False, attack_type="TIMEOUT",
                    explanation=f"Timed out after {self.timeout_seconds}s.",
                    states_visited=states_visited,
                    time_seconds=time.time() - t0,
                    sessions_bound=self.max_sessions,
                )

            state, depth = queue.popleft()
            states_visited += 1

            if depth > self.depth_limit:
                continue

            key = state.key()
            if key in visited:
                continue
            visited.add(key)

            if self.verbose and states_visited % 1000 == 0:
                print(f"  BFS states={states_visited} depth={depth} "
                      f"queue={len(queue)}")

            # Check properties
            violations = run_all_checkers(
                state.to_ps(),
                secrecy_terms=secrecy_terms,
                initiator_role=init_role,
                responder_role=resp_role,
            )
            if violations:
                v = violations[0]
                return VerificationResult(
                    attack_found=True,
                    attack_type=v.attack_type,
                    property=v.property,
                    trace=state.trace + v.trace,
                    explanation=v.explanation,
                    states_visited=states_visited,
                    time_seconds=time.time() - t0,
                    sessions_bound=self.max_sessions,
                )

            if len(queue) < MAX_QUEUE:
                for succ in self._successors(state, protocol):
                    queue.append((succ, depth + 1))

        return VerificationResult(
            attack_found=False,
            states_visited=states_visited,
            time_seconds=time.time() - t0,
            sessions_bound=self.max_sessions,
            explanation="No attack found within bounded verification.",
        )

    # ── Pass 1: honest run ────────────────────────────────────────────────

    def _honest_run(
        self, protocol: ProtocolDef,
        secrecy_terms: list, init_role: str, resp_role: str
    ) -> Optional[CheckerResult]:
        sessions = [Session(session_id=i, role=r)
                    for i, r in enumerate(protocol.roles)]
        atk = AttackerKnowledge(lazy=True)
        for t in protocol.public_values:
            atk.add(t)
        atk.close()
        history: List[Tuple[int, bool, Term]] = []

        for _ in range(sum(len(r.steps) for r in protocol.roles) + 5):
            all_done = True
            for sess in sessions:
                if sess.completed:
                    continue
                all_done = False
                step = sess.role.steps[sess.step_index]
                concrete = substitute(step.term, sess.bindings)
                if _has_var(concrete):
                    continue
                if step.send:
                    atk.learn_from(concrete)
                    history.append((sess.session_id, True, concrete))
                    sess.advance()
                else:
                    delivered = self._honest_deliver(concrete, atk)
                    if delivered is None:
                        continue
                    env = match(concrete, delivered, dict(sess.bindings))
                    if env is None:
                        continue
                    sess.bindings.update(env)
                    history.append((sess.session_id, False, delivered))
                    sess.advance()
            if all_done:
                break

        ps = ProtocolState(sessions=sessions, attacker=atk)
        ps.history = history
        for sid, is_send, term in history:
            ps.sent_messages.append(
                (sid, Message(send=is_send, sender="?",
                              receiver="?", term=term))
            )
        violations = run_all_checkers(
            ps, secrecy_terms=secrecy_terms,
            initiator_role=init_role, responder_role=resp_role,
        )
        return violations[0] if violations else None

    # ── Collect honest material ───────────────────────────────────────────

    def _collect_honest_material(self, protocol: ProtocolDef) -> List[Term]:
        """
        Collect all terms the attacker can intercept from the honest run:
        - Encrypt terms (seen but not decryptable without key)
        - Plaintext Atoms sent directly (e.g. Na in ISO9798 M1: "A, Na")
        """
        sessions = [Session(session_id=i, role=r)
                    for i, r in enumerate(protocol.roles)]
        atk = AttackerKnowledge(lazy=True)
        for t in protocol.public_values:
            atk.add(t)
        atk.close()
        material: List[Term] = []

        for _ in range(40):
            all_done = True
            for sess in sessions:
                if sess.completed:
                    continue
                all_done = False
                step = sess.role.steps[sess.step_index]
                concrete = substitute(step.term, sess.bindings)
                if _has_var(concrete):
                    continue
                if step.send:
                    atk.learn_from(concrete)
                    self._extract_material(concrete, material)
                    sess.advance()
                else:
                    delivered = self._honest_deliver(concrete, atk)
                    if delivered is None:
                        continue
                    env = match(concrete, delivered, dict(sess.bindings))
                    if env is None:
                        continue
                    sess.bindings.update(env)
                    sess.advance()
            if all_done:
                break
        return material

    def _extract_material(self, term: Term, out: List[Term]) -> None:
        """Extract Encrypt terms and plaintext Atoms recursively."""
        if isinstance(term, Encrypt):
            out.append(term)
        elif isinstance(term, Atom):
            out.append(term)
        elif isinstance(term, (Concat, Pair)):
            l = term.left  if isinstance(term, Concat) else term.first
            r = term.right if isinstance(term, Concat) else term.second
            self._extract_material(l, out)
            self._extract_material(r, out)
        # Don't recurse into DH/Hash — those are one-way

    # ── Initial state ─────────────────────────────────────────────────────

    def _initial_state(
        self, protocol: ProtocolDef, honest_material: List[Term]
    ) -> _State:
        sessions = [Session(session_id=i, role=r)
                    for i, r in enumerate(protocol.roles)]
        atk = AttackerKnowledge(lazy=True)
        for t in protocol.public_values:
            atk.add(t)
        for name in _ATTACKER_OWN:
            atk.add(Atom(name))
        # Attacker intercepts all honest-run material
        for m in honest_material:
            atk.learn_from(m)
        atk.close()
        return _State(sessions=sessions, attacker=atk, history=[], trace=[])

    # ── Successors ────────────────────────────────────────────────────────

    def _successors(self, state: _State, protocol: ProtocolDef) -> List[_State]:
        successors: List[_State] = []
        role_counts: Dict[str, int] = {}
        for s in state.sessions:
            role_counts[s.role.name] = role_counts.get(s.role.name, 0) + 1

        for session in state.sessions:
            if session.completed:
                continue
            step = session.role.steps[session.step_index]

            if step.send:
                succ = self._do_send(state, session, step)
                if succ:
                    successors.append(succ)
            else:
                for term in self._candidates(
                    step.term, state.attacker, session.bindings, state.history
                ):
                    succ = self._do_recv(state, session, step, term)
                    if succ:
                        successors.append(succ)

        for role in protocol.roles:
            if role_counts.get(role.name, 0) < self.max_sessions:
                succ = state.copy()
                new_id = max(
                    (s.session_id for s in state.sessions), default=-1
                ) + 1
                succ.sessions.append(Session(session_id=new_id, role=role))
                succ.trace.append(f"[new {new_id}:{role.name}]")
                successors.append(succ)

        return successors

    def _do_send(
        self, state: _State, session: Session, step: Message
    ) -> Optional[_State]:
        concrete = substitute(step.term, session.bindings)
        if _has_var(concrete):
            return None
        succ = state.copy()
        sess = _get(succ.sessions, session.session_id)
        succ.attacker.learn_from(concrete)
        succ.history.append((session.session_id, True, concrete))
        succ.trace.append(
            f"[{session.session_id}:{session.role.name}] "
            f"SEND {step.label}: {concrete}"
        )
        sess.advance()
        if sess.completed:
            succ.trace.append(
                f"[{session.session_id}:{session.role.name}] ✓ done"
            )
        return succ

    def _do_recv(
        self, state: _State, session: Session, step: Message, delivered: Term
    ) -> Optional[_State]:
        pattern = substitute(step.term, session.bindings)
        env = match(pattern, delivered, dict(session.bindings))
        if env is None:
            return None
        succ = state.copy()
        sess = _get(succ.sessions, session.session_id)
        sess.bindings.update(env)
        succ.history.append((session.session_id, False, delivered))
        succ.trace.append(
            f"[{session.session_id}:{session.role.name}] "
            f"RECV {step.label}: {delivered}"
        )
        sess.advance()
        if sess.completed:
            succ.trace.append(
                f"[{session.session_id}:{session.role.name}] ✓ done"
            )
        return succ

    def _candidates(
        self,
        pattern: Term,
        attacker: AttackerKnowledge,
        bindings: Dict[str, Term],
        history: List[Tuple[int, bool, Term]],
    ) -> List[Term]:
        """
        Up to MAX_CANDS candidate terms for delivery.

        Priority:
          1. Honest expected term (built from pattern + current bindings)
          2. Protocol atoms from plaintext history (Na, K_AB, etc. — NOT attacker-own)
          3. Intercepted Encrypt terms (replay/reflection material)
          4. Attacker's own key atoms
          5. Remaining known terms
        """
        seen: Set[str] = set()
        result: List[Term] = []

        def add(t: Term) -> None:
            k = repr(t)
            if k not in seen and len(result) < MAX_CANDS:
                seen.add(k)
                result.append(t)

        resolved = substitute(pattern, bindings)

        # 1. Honest expected term
        honest = self._honest_deliver(resolved, attacker)
        if honest is not None:
            add(honest)

        # 2. Protocol atoms from plaintext history (NOT attacker-own atoms)
        for _, is_send, term in history:
            if is_send and isinstance(term, Atom):
                if term.name not in _ATTACKER_OWN:
                    add(term)

        # 3. Intercepted Encrypt terms
        for _, is_send, term in reversed(history):
            if is_send and isinstance(term, Encrypt):
                add(term)

        # 4. Attacker's own key atoms
        for name in sorted(_ATTACKER_OWN):
            a = Atom(name)
            if attacker.knows(a):
                add(a)

        # 5. All known atoms
        for t in attacker.snapshot():
            if isinstance(t, Atom):
                add(t)

        # 6. Remaining structured terms
        for t in attacker.snapshot():
            add(t)

        return result

    def _honest_deliver(
        self, pattern: Term, atk: AttackerKnowledge
    ) -> Optional[Term]:
        """Build the expected receive term from attacker knowledge."""
        if isinstance(pattern, Variable):
            snap = [t for t in atk.snapshot() if isinstance(t, Atom)
                    and t.name not in _ATTACKER_OWN]
            return snap[0] if snap else None
        if isinstance(pattern, Atom):
            return pattern
        if isinstance(pattern, Encrypt):
            p = self._honest_deliver(pattern.payload, atk)
            k = self._honest_deliver(pattern.key, atk)
            return Encrypt(p, k) if p is not None and k is not None else None
        if isinstance(pattern, Concat):
            l = self._honest_deliver(pattern.left, atk)
            r = self._honest_deliver(pattern.right, atk)
            return Concat(l, r) if l is not None and r is not None else None
        if isinstance(pattern, Pair):
            l = self._honest_deliver(pattern.first, atk)
            r = self._honest_deliver(pattern.second, atk)
            return Pair(l, r) if l is not None and r is not None else None
        if isinstance(pattern, Hash):
            c = self._honest_deliver(pattern.content, atk)
            return Hash(c) if c is not None else None
        if isinstance(pattern, DH):
            b = self._honest_deliver(pattern.base, atk)
            e = self._honest_deliver(pattern.exponent, atk)
            return DH(b, e) if b is not None and e is not None else None
        return None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _has_var(term: Term) -> bool:
    if isinstance(term, Variable):
        return True
    if isinstance(term, Atom):
        return False
    if isinstance(term, Encrypt):
        return _has_var(term.payload) or _has_var(term.key)
    if isinstance(term, Concat):
        return _has_var(term.left) or _has_var(term.right)
    if isinstance(term, Pair):
        return _has_var(term.first) or _has_var(term.second)
    if isinstance(term, Hash):
        return _has_var(term.content)
    if isinstance(term, DH):
        return _has_var(term.base) or _has_var(term.exponent)
    return False


def _get(sessions: List[Session], sid: int) -> Session:
    for s in sessions:
        if s.session_id == sid:
            return s
    raise KeyError(f"Session {sid} not found")
