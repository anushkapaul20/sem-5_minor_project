"""
engine/
=======
QuantumScyther AI — Custom Dolev-Yao Verification Engine

Modules
-------
terms       — Term algebra (Atom, Encrypt, Hash, Concat, DH, Pair)
dolev_yao   — Attacker model + deduction closure
protocol    — Protocol state machine (roles, sessions, transitions)
explorer    — Bounded BFS model checker (max 2 sessions)
checkers    — Property checkers (Secrecy, Auth, Replay, Reflection, MITM, UKS)
benchmark   — Benchmark validation runner
pqc/        — Post-quantum primitive flagging

Architectural rule
------------------
This engine is the ONLY component that makes security decisions.
LLMs (ai/) handle translation and explanation — never detection.
"""
