"""
engine/protocols/nspk.py
========================
Needham-Schroeder Public Key Protocol (NSPK) — MITM vulnerable.
Needham-Schroeder-Lowe (NSL) — SECURE fix.

Sources
-------
NSPK: Needham, R.M.; Schroeder, M.D. CACM 21(12):993-999, 1978.
NSL : Lowe, G. TACAS 1996, LNCS 1055, pp.147-166.

Key modelling
-------------
  Ka_dec = A's private decryption key (only A holds — NOT public)
  Kb_dec = B's private decryption key (only B holds — NOT public)
  Ka_enc = A's public encryption key  (everyone knows — used to encrypt TO A)
  Kb_enc = B's public encryption key  (everyone knows — used to encrypt TO B)
  Ke_dec = E's private key (attacker's — public so attacker can be spoken to)
  Ke_enc = E's public key  (attacker's)

In Dolev-Yao: Encrypt(m, Ka_dec) is only decryptable if attacker knows Ka_dec.
Attacker knows Ka_enc, Kb_enc, Ke_enc, Ke_dec — NOT Ka_dec or Kb_dec.

Variable naming convention (CRITICAL for checker correctness)
-------------------------------------------------------------
Shared variables MUST use the same name across roles so the
authentication checker can detect conflicts:
  "Na"  — A's nonce (sent by I, received back by I in M2)
  "Nb"  — B's nonce (sent by R in M2, received by R in M3)

NSPK: M1 A→B: {Na,A}Kb_dec | M2 B→A: {Na,Nb}Ka_dec | M3 A→B: {Nb}Kb_dec
NSL:  M1 A→B: {Na,A}Kb_dec | M2 B→A: {Na,Nb,B}Ka_dec | M3 A→B: {Nb}Kb_dec
"""

from engine.terms import Atom, Concat, Encrypt
from engine.unifier import Variable
from engine.protocol import AuthClaim, Message, ProtocolDef, Role, SecrecyClaim


def make_nspk() -> ProtocolDef:
    """NSPK — MITM vulnerable. Expected: ATTACK FOUND."""
    Ka_dec = Atom("Ka_dec")   # A's private key — NOT in public_values
    Kb_dec = Atom("Kb_dec")   # B's private key — NOT in public_values
    Ka_enc = Atom("Ka_enc")   # A's public key
    Kb_enc = Atom("Kb_enc")   # B's public key
    Ke_dec = Atom("Ke_dec")   # E's private key
    Ke_enc = Atom("Ke_enc")   # E's public key
    A      = Atom("A")
    B      = Atom("B")
    Na     = Atom("Na")       # A's fresh nonce (fixed symbolic value)
    Nb     = Atom("Nb")       # B's fresh nonce (fixed symbolic value)

    # ── Initiator (A) ──────────────────────────────────────────────────────
    # Variable "Na" — in M2 receipt, A checks the nonce it sent
    # Variable "Nb" — in M2 receipt, A learns B's nonce; resends in M3
    # Variable "partner" — who A thinks B is (detected via Ke_enc in MITM)
    initiator = Role("I", steps=[
        # M1: send {Na, A}Kb_dec
        Message(send=True,  sender="I", receiver="R",
                term=Encrypt(Concat(Na, A), Kb_dec), label="M1"),
        # M2: receive {Na, Nb}Ka_dec — both nonces
        Message(send=False, sender="R", receiver="I",
                term=Encrypt(Concat(Variable("Na"), Variable("Nb")), Ka_dec),
                label="M2"),
        # M3: send {Nb}Kb_dec
        Message(send=True,  sender="I", receiver="R",
                term=Encrypt(Variable("Nb"), Kb_dec), label="M3"),
    ])

    # ── Responder (B) ──────────────────────────────────────────────────────
    # Variable "Na" — R learns Na from M1; echoes it in M2
    # Variable "Nb" — R checks M3 matches what it sent
    responder = Role("R", steps=[
        # M1: receive {Na, A}Kb_dec
        Message(send=False, sender="I", receiver="R",
                term=Encrypt(Concat(Variable("Na"), Variable("A_id")), Kb_dec),
                label="M1"),
        # M2: send {Na, Nb}Ka_dec  (Nb is the fixed atom R generates)
        Message(send=True,  sender="R", receiver="I",
                term=Encrypt(Concat(Variable("Na"), Nb), Ka_dec), label="M2"),
        # M3: receive {Nb}Kb_dec — must be exactly Nb, not any Variable
        Message(send=False, sender="I", receiver="R",
                term=Encrypt(Nb, Kb_dec), label="M3"),
    ])

    return ProtocolDef(
        name="NSPK",
        roles=[initiator, responder],
        secrecy_claims=[SecrecyClaim(Na, "I"), SecrecyClaim(Nb, "R")],
        auth_claims=[AuthClaim("I", "R")],
        # Private keys Ka_dec, Kb_dec NOT in public_values
        public_values=[Ka_enc, Kb_enc, Ke_enc, Ke_dec, A, B],
    )


def make_nsl() -> ProtocolDef:
    """NSL — Lowe fix. Expected: SECURE."""
    Ka_dec = Atom("Ka_dec")
    Kb_dec = Atom("Kb_dec")
    Ka_enc = Atom("Ka_enc")
    Kb_enc = Atom("Kb_enc")
    Ke_dec = Atom("Ke_dec")
    Ke_enc = Atom("Ke_enc")
    A      = Atom("A")
    B      = Atom("B")
    Na     = Atom("Na")
    Nb     = Atom("Nb")

    initiator = Role("I", steps=[
        # M1: {Na, A}Kb_dec
        Message(send=True,  sender="I", receiver="R",
                term=Encrypt(Concat(Na, A), Kb_dec), label="M1"),
        # M2: receive {Na, Nb, B}Ka_dec  — B's identity included
        Message(send=False, sender="R", receiver="I",
                term=Encrypt(Concat(Variable("Na"),
                             Concat(Variable("Nb"), Variable("B_id"))),
                             Ka_dec), label="M2"),
        # M3: {Nb}Kb_dec
        Message(send=True,  sender="I", receiver="R",
                term=Encrypt(Variable("Nb"), Kb_dec), label="M3"),
    ])

    responder = Role("R", steps=[
        # M1: receive {Na, A}Kb_dec
        Message(send=False, sender="I", receiver="R",
                term=Encrypt(Concat(Variable("Na"), Variable("A_id")), Kb_dec),
                label="M1"),
        # M2: send {Na, Nb, B}Ka_dec  (Nb is the fixed nonce R generated)
        Message(send=True,  sender="R", receiver="I",
                term=Encrypt(Concat(Variable("Na"), Concat(Nb, B)),
                             Ka_dec), label="M2"),
        # M3: receive {Nb}Kb_dec — must be exactly Nb (the atom R sent), not a Variable
        Message(send=False, sender="I", receiver="R",
                term=Encrypt(Nb, Kb_dec), label="M3"),
    ])

    return ProtocolDef(
        name="NSL",
        roles=[initiator, responder],
        secrecy_claims=[SecrecyClaim(Na, "I"), SecrecyClaim(Nb, "R")],
        auth_claims=[AuthClaim("I", "R")],
        public_values=[Ka_enc, Kb_enc, Ke_enc, Ke_dec, A, B],
    )
