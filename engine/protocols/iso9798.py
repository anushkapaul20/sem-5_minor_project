"""
engine/protocols/iso9798.py
============================
ISO/IEC 9798-2 style mutual authentication — Reflection vulnerable.

Source: Syverson 1994, Bird et al. 1993.

M1: A→B: A, Na
M2: B→A: {Na}K_AB, Nb
M3: A→B: {Nb}K_AB

Reflection attack: E opens two sessions with B.
  Session 1: E sends Na as challenge, B responds with {Na}K_AB, Nb
  Session 2: E uses Nb as challenge, B responds with {Nb}K_AB — gives E M3!
  E completes session 1 with {Nb}K_AB

Variable naming: "Na" and "Nb" consistent across both roles.
"""

from engine.terms import Atom, Concat, Encrypt
from engine.unifier import Variable
from engine.protocol import AuthClaim, Message, ProtocolDef, Role, SecrecyClaim


def make_iso9798() -> ProtocolDef:
    K_AB = Atom("K_AB")   # shared symmetric key — NOT in public_values
    A    = Atom("A")
    B    = Atom("B")
    Na   = Atom("Na")     # initiator's challenge nonce
    Nb   = Atom("Nb")     # responder's challenge nonce

    initiator = Role("I", steps=[
        # M1: A, Na  (Na sent in plaintext — attacker intercepts it)
        Message(send=True, sender="I", receiver="R",
                term=Concat(A, Na), label="M1"),
        # M2: receive {Na}K_AB, Nb  (Na echoed back, learn Nb)
        Message(send=False, sender="R", receiver="I",
                term=Concat(Encrypt(Variable("Na"), K_AB), Variable("Nb")),
                label="M2"),
        # M3: send {Nb}K_AB  (Nb is now bound from M2)
        Message(send=True, sender="I", receiver="R",
                term=Encrypt(Variable("Nb"), K_AB), label="M3"),
    ])

    responder = Role("R", steps=[
        # M1: receive A, Na  (Na becomes known to R)
        Message(send=False, sender="I", receiver="R",
                term=Concat(Variable("A_id"), Variable("Na")), label="M1"),
        # M2: send {Na}K_AB, Nb  (Nb is the fixed atom R generates)
        Message(send=True, sender="R", receiver="I",
                term=Concat(Encrypt(Variable("Na"), K_AB), Nb), label="M2"),
        # M3: receive {Nb}K_AB — must match exactly Nb (not any Variable)
        Message(send=False, sender="I", receiver="R",
                term=Encrypt(Nb, K_AB), label="M3"),
    ])

    return ProtocolDef(
        name="ISO9798",
        roles=[initiator, responder],
        secrecy_claims=[],
        auth_claims=[AuthClaim("I", "R")],
        public_values=[A, B],   # K_AB NOT public
    )
