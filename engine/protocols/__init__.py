"""
engine/protocols/
=================
Hand-coded ProtocolDef instances for all 6 benchmark protocols.

Each protocol is encoded exactly as it appears in its source paper.
These are used for:
  1. Engine benchmark validation (target ≥ 85% accuracy)
  2. Integration tests

Protocols
---------
nspk    — Needham-Schroeder Public Key (MITM vulnerable)
nsl     — Needham-Schroeder-Lowe (SECURE fix)
nssk    — Needham-Schroeder Symmetric Key (Replay vulnerable)
iso9798 — ISO/IEC 9798-2 style (Reflection vulnerable)
sts     — Station-to-Station (UKS vulnerable)
mqv     — MQV key agreement (KCI vulnerable)
"""

from engine.protocols.nspk    import make_nspk, make_nsl
from engine.protocols.nssk    import make_nssk
from engine.protocols.iso9798 import make_iso9798
from engine.protocols.sts     import make_sts
from engine.protocols.mqv     import make_mqv

__all__ = [
    "make_nspk", "make_nsl",
    "make_nssk",
    "make_iso9798",
    "make_sts",
    "make_mqv",
]
