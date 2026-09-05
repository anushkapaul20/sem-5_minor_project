"""
engine/protocol.py
==================
Protocol state machine for QuantumScyther AI.

Represents a cryptographic protocol as a set of roles,
each with a sequence of send/receive events. The engine
can execute the protocol honestly (no attacker) or with
Dolev-Yao attacker interleaving (see explorer.py).

Key classes
-----------
Message     — one send/receive step: (sender, receiver, term)
Role        — sequence of steps for one participant (e.g. Initiator)
ProtocolDef — complete protocol: list of roles + claimed properties
Session     — one running instance of a role, with local variable bindings
ProtocolState — snapshot: all running sessions + attacker knowledge

Usage
-----
    from engine.terms import Atom, Encrypt, Concat
    from engine.protocol import Message, Role, ProtocolDef

    Na, Nb, Ka, Kb, A, B = (Atom(x) for x in ["Na","Nb","Ka","Kb","A","B"])

    initiator = Role("I", [
        Message(send=True,  sender="I", receiver="R", term=Encrypt(Concat(Na, A), Kb)),
        Message(send=False, sender="R", receiver="I", term=Encrypt(Concat(Na, Nb), Ka)),
        Message(send=True,  sender="I", receiver="R", term=Encrypt(Nb, Kb)),
    ])

    responder = Role("R", [
        Message(send=False, sender="I", receiver="R", term=Encrypt(Concat(Na, A), Kb)),
        Message(send=True,  sender="R", receiver="I", term=Encrypt(Concat(Na, Nb), Ka)),
        Message(send=False, sender="I", receiver="R", term=Encrypt(Nb, Kb)),
    ])

    nspk = ProtocolDef(
        name="NSPK",
        roles=[initiator, responder],
        secrecy_claims=[Na, Nb],
        auth_claims=[("I", "R")],
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from engine.terms import Atom, Term
from engine.dolev_yao import AttackerKnowledge


# ── Message ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Message:
    """
    One send or receive event in a protocol role.

    Parameters
    ----------
    send     : True = this role SENDS this message; False = RECEIVES
    sender   : role name of the sender   (e.g. "I" for Initiator)
    receiver : role name of the receiver (e.g. "R" for Responder)
    term     : the symbolic term being sent/received
    step     : position in the role's step sequence (0-indexed)
    label    : human-readable label (e.g. "M1", "Step 2")
    """
    send:     bool
    sender:   str
    receiver: str
    term:     Term
    step:     int = 0
    label:    str = ""

    def __str__(self) -> str:
        direction = "→" if self.send else "←"
        return f"[{self.label or self.step}] {self.sender} {direction} {self.receiver} : {self.term}"


# ── Role ───────────────────────────────────────────────────────────────────────

@dataclass
class Role:
    """
    A named sequence of send/receive steps.

    Parameters
    ----------
    name     : role identifier, e.g. "I" (Initiator) or "R" (Responder)
    steps    : ordered list of Messages
    """
    name:  str
    steps: List[Message] = field(default_factory=list)

    def __post_init__(self):
        # Stamp each step with its index and the role name
        for i, msg in enumerate(self.steps):
            object.__setattr__(msg, "step", i)

    def __repr__(self) -> str:
        return f"Role({self.name!r}, {len(self.steps)} steps)"


# ── Security claims ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SecrecyClaim:
    """Claim that `term` should never be known to the attacker."""
    term: Term
    owner: str   # role name that owns this secret

@dataclass(frozen=True)
class AuthClaim:
    """
    Claim that when role `responder` completes, there must be a matching
    run by role `initiator` with the same session parameters.
    (Non-injective agreement)
    """
    initiator: str
    responder: str


# ── Protocol Definition ────────────────────────────────────────────────────────

@dataclass
class ProtocolDef:
    """
    Complete definition of a cryptographic protocol.

    Parameters
    ----------
    name            : protocol name, e.g. "NSPK"
    roles           : list of Role objects
    secrecy_claims  : terms that must remain secret from the attacker
    auth_claims     : (initiator, responder) authentication pairs
    public_values   : terms that are publicly known at the start
                      (e.g. public keys, generator g, identities)
    """
    name:           str
    roles:          List[Role]         = field(default_factory=list)
    secrecy_claims: List[SecrecyClaim] = field(default_factory=list)
    auth_claims:    List[AuthClaim]    = field(default_factory=list)
    public_values:  List[Term]         = field(default_factory=list)

    def role(self, name: str) -> Optional[Role]:
        """Look up a role by name."""
        for r in self.roles:
            if r.name == name:
                return r
        return None

    def __repr__(self) -> str:
        return (
            f"ProtocolDef({self.name!r}, "
            f"{len(self.roles)} roles, "
            f"{len(self.secrecy_claims)} secrecy claims, "
            f"{len(self.auth_claims)} auth claims)"
        )


# ── Session ────────────────────────────────────────────────────────────────────

@dataclass
class Session:
    """
    One running instance of a Role.

    A session tracks:
      - which role is being executed
      - how many steps have completed
      - the local variable bindings (nonces generated, values received)
      - the session ID (used to distinguish parallel sessions)

    Parameters
    ----------
    session_id : unique integer identifier for this session
    role       : the Role being executed
    bindings   : mapping from variable/nonce name → concrete Term
    step_index : next step to execute (0 = not started)
    completed  : True when all steps are done
    """
    session_id:  int
    role:        Role
    bindings:    Dict[str, Term] = field(default_factory=dict)
    step_index:  int             = 0
    completed:   bool            = False

    def current_step(self) -> Optional[Message]:
        """Return the next Message to execute, or None if done."""
        if self.step_index < len(self.role.steps):
            return self.role.steps[self.step_index]
        return None

    def advance(self) -> None:
        """Move to the next step."""
        self.step_index += 1
        if self.step_index >= len(self.role.steps):
            self.completed = True

    def bind(self, name: str, term: Term) -> None:
        """Store a name → term binding in this session."""
        self.bindings[name] = term

    def resolve(self, term: Term) -> Term:
        """
        Substitute any Atom whose name appears in bindings with its value.
        Non-recursive for now — deep substitution handled by explorer.
        """
        if isinstance(term, Atom) and term.name in self.bindings:
            return self.bindings[term.name]
        return term

    def copy(self) -> "Session":
        return Session(
            session_id=self.session_id,
            role=self.role,
            bindings=dict(self.bindings),
            step_index=self.step_index,
            completed=self.completed,
        )

    def __repr__(self) -> str:
        return (
            f"Session(id={self.session_id}, role={self.role.name!r}, "
            f"step={self.step_index}/{len(self.role.steps)}, "
            f"done={self.completed})"
        )


# ── Protocol State ─────────────────────────────────────────────────────────────

@dataclass
class ProtocolState:
    """
    A complete snapshot of the protocol execution at one point in time.
    """
    sessions:            List[Session]             = field(default_factory=list)
    attacker:            AttackerKnowledge         = field(default_factory=AttackerKnowledge)
    sent_messages:       List[Tuple[int, "Message"]] = field(default_factory=list)
    completed_sessions:  Set[int]                  = field(default_factory=set)
    attack_trace:        List[str]                 = field(default_factory=list)
    # Raw (session_id, is_send, term) history — populated by explorer
    history:             List[Tuple[int, bool, "Term"]] = field(default_factory=list)

    def copy(self) -> "ProtocolState":
        """Deep copy for BFS branching."""
        ps = ProtocolState(
            sessions=[s.copy() for s in self.sessions],
            attacker=self.attacker.copy(),
            sent_messages=list(self.sent_messages),
            completed_sessions=set(self.completed_sessions),
            attack_trace=list(self.attack_trace),
            history=list(self.history),
        )
        return ps

    def session(self, session_id: int) -> Optional[Session]:
        for s in self.sessions:
            if s.session_id == session_id:
                return s
        return None

    def active_sessions(self) -> List[Session]:
        return [s for s in self.sessions if not s.completed]

    def all_completed(self) -> bool:
        return all(s.completed for s in self.sessions)

    def __repr__(self) -> str:
        active = sum(1 for s in self.sessions if not s.completed)
        return (
            f"ProtocolState("
            f"{len(self.sessions)} sessions, "
            f"{active} active, "
            f"attacker knows {len(self.attacker)} terms)"
        )


# ── Standalone demo ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from engine.terms import Concat, Encrypt

    Na = Atom("Na")
    Nb = Atom("Nb")
    Ka = Atom("Ka")
    Kb = Atom("Kb")
    A  = Atom("A")

    # Define NSPK initiator role
    initiator = Role("I", steps=[
        Message(True,  "I", "R", Encrypt(Concat(Na, A), Kb), label="M1"),
        Message(False, "R", "I", Encrypt(Concat(Na, Nb), Ka), label="M2"),
        Message(True,  "I", "R", Encrypt(Nb, Kb), label="M3"),
    ])

    responder = Role("R", steps=[
        Message(False, "I", "R", Encrypt(Concat(Na, A), Kb), label="M1"),
        Message(True,  "R", "I", Encrypt(Concat(Na, Nb), Ka), label="M2"),
        Message(False, "I", "R", Encrypt(Nb, Kb), label="M3"),
    ])

    nspk = ProtocolDef(
        name="NSPK",
        roles=[initiator, responder],
        secrecy_claims=[SecrecyClaim(Na, "I"), SecrecyClaim(Nb, "R")],
        auth_claims=[AuthClaim("I", "R")],
        public_values=[Ka, Kb, A, Atom("B")],
    )

    print(nspk)
    for role in nspk.roles:
        print(f"\n  {role}")
        for step in role.steps:
            print(f"    {step}")
