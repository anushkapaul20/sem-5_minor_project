"""
engine/protocols/sts.py
=======================
Station-to-Station (STS) — UKS vulnerable.

Sources: Diffie-vanOorschot-Wiener 1992, Blake-Wilson & Menezes 1999.

M1: A→B: gx = g^x
M2: B→A: gy, Cert_B, {sig_B(gy||gx)}K
M3: A→B: Cert_A, {sig_A(gx||gy)}K
where K = g^(xy)

UKS: E substitutes Cert_B with Cert_E and re-signs.
A believes she talks to E; B believes he talks to A.

Variable naming:
  "gx" — A's DH value (sent by I, received back by R)
  "gy" — B's DH value (sent by R, received by I)
  "cert_peer" — the certificate of the responder (E substitutes this)
"""

from engine.terms import Atom, Concat, DH, Encrypt
from engine.unifier import Variable
from engine.protocol import AuthClaim, Message, ProtocolDef, Role, SecrecyClaim


def make_sts() -> ProtocolDef:
    g      = Atom("g")
    x      = Atom("x")
    y      = Atom("y")
    gx     = DH(g, x)
    gy     = DH(g, y)
    K      = DH(gx, y)    # session key g^(xy)

    sk_A   = Atom("sk_A")  # A's signing key — NOT public
    sk_B   = Atom("sk_B")  # B's signing key — NOT public
    sk_E   = Atom("sk_E")  # E's signing key — attacker knows it
    Cert_A = Atom("Cert_A")
    Cert_B = Atom("Cert_B")
    Cert_E = Atom("Cert_E")
    A      = Atom("A")
    B      = Atom("B")

    # ── Initiator (A) ──────────────────────────────────────────────────────
    initiator = Role("I", steps=[
        # M1: gx
        Message(send=True, sender="I", receiver="R",
                term=gx, label="M1"),
        # M2: receive gy, Cert_peer, {sig_peer(gy||gx)}K
        # cert_peer will be Cert_E (not Cert_B) in the UKS attack
        Message(send=False, sender="R", receiver="I",
                term=Concat(Variable("gy"),
                     Concat(Variable("cert_peer"),
                            Encrypt(Variable("sig_peer"),
                                    Variable("K_recv")))),
                label="M2"),
        # M3: Cert_A, {sig_A(gx||gy)}K
        Message(send=True, sender="I", receiver="R",
                term=Concat(Cert_A,
                            Encrypt(Encrypt(Concat(gx, Variable("gy")), sk_A),
                                    Variable("K_recv"))),
                label="M3"),
    ])

    # ── Responder (B) ──────────────────────────────────────────────────────
    responder = Role("R", steps=[
        # M1: receive gx
        Message(send=False, sender="I", receiver="R",
                term=Variable("gx"), label="M1"),
        # M2: gy, Cert_B, {sig_B(gy||gx)}K
        Message(send=True, sender="R", receiver="I",
                term=Concat(gy,
                     Concat(Cert_B,
                            Encrypt(Encrypt(Concat(gy, Variable("gx")), sk_B),
                                    DH(Variable("gx"), y)))),
                label="M2"),
        # M3: receive Cert_init, sig_blob
        Message(send=False, sender="I", receiver="R",
                term=Concat(Variable("cert_init"), Variable("sig_blob")),
                label="M3"),
    ])

    return ProtocolDef(
        name="STS",
        roles=[initiator, responder],
        secrecy_claims=[SecrecyClaim(K, "I")],
        auth_claims=[AuthClaim("I", "R")],
        # sk_A, sk_B NOT public. sk_E public (attacker's own key)
        public_values=[g, gx, gy, Cert_A, Cert_B, Cert_E, A, B, sk_E],
    )
