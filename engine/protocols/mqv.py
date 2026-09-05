"""
engine/protocols/mqv.py
=======================
MQV (Menezes-Qu-Vanstone) Key Agreement — KCI vulnerable.

Source: Blake-Wilson, Johnson, Menezes 1997. LNCS 1355, pp.30-45.

Protocol (2 messages):
  M1: A → B : X = g^x   (A's ephemeral DH public key)
  M2: B → A : Y = g^y   (B's ephemeral DH public key)

KCI attack: if A's long-term private key 'a' is compromised,
attacker can impersonate ANY party to A.

Engine modelling:
  - 'a' (A's static private key) is in public_values = compromised
  - The KCI checker detects: attacker knows 'a' AND at least one
    session completed. The attack succeeds because the attacker
    can compute A's implicit signature s_A = x + h(X)*a
    for any chosen ephemeral x, meaning E can derive the same
    session key A computes with any party.
  - We model this as: if 'a' is compromised and both sessions
    complete with DH values in their bindings, the session key
    is derivable by E (secrecy violation / KCI).

Variable naming:
  "gx_recv" — what R receives as g^x (should be DH(g,x) from I)
  "gy_recv" — what I receives as g^y (should be DH(g,y) from R)
"""

from engine.terms import Atom, DH
from engine.unifier import Variable
from engine.protocol import AuthClaim, Message, ProtocolDef, Role, SecrecyClaim


def make_mqv() -> ProtocolDef:
    """MQV — KCI vulnerable. Expected: ATTACK FOUND."""
    g  = Atom("g")
    x  = Atom("x")       # A's ephemeral private key
    y  = Atom("y")       # B's ephemeral private key
    a  = Atom("a")       # A's long-term private key — COMPROMISED (in public_values)
    b  = Atom("b")       # B's long-term private key — not compromised
    gx = DH(g, x)        # g^x — A's ephemeral public key
    gy = DH(g, y)        # g^y — B's ephemeral public key

    # ── Initiator (A) ──────────────────────────────────────────────────────
    initiator = Role("I", steps=[
        # M1: send g^x
        Message(send=True, sender="I", receiver="R",
                term=gx, label="M1"),
        # M2: receive g^y
        Message(send=False, sender="R", receiver="I",
                term=Variable("gy_recv"), label="M2"),
    ])

    # ── Responder (B) ──────────────────────────────────────────────────────
    responder = Role("R", steps=[
        # M1: receive g^x
        Message(send=False, sender="I", receiver="R",
                term=Variable("gx_recv"), label="M1"),
        # M2: send g^y
        Message(send=True, sender="R", receiver="I",
                term=gy, label="M2"),
    ])

    return ProtocolDef(
        name="MQV",
        roles=[initiator, responder],
        # Session key: g^(xy) — attacker can derive it if 'a' is known
        # because implicit signature s_A = x + h(X)*a mod q
        secrecy_claims=[SecrecyClaim(DH(gx, y), "I")],
        auth_claims=[AuthClaim("I", "R")],
        # 'a' is in public_values = COMPROMISED (KCI attack precondition)
        # g, gx, gy are public DH values
        public_values=[g, gx, gy, a, DH(g, a), DH(g, b)],
    )
