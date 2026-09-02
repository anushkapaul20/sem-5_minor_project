# QuantumScyther AI

**AI-Powered Cryptographic Protocol Verification with Post-Quantum Awareness**  
B.Tech Minor Project — Semester 5 | August 2026

---

## What This Does

QuantumScyther AI accepts a cryptographic protocol (written in LaTeX notation or YAML), verifies it for security vulnerabilities using a **custom-built symbolic engine**, explains any attack found in plain English using an LLM, and flags primitives that are **broken by quantum computers**.

```
You type:                    You get back:
─────────────────────────    ─────────────────────────────────────────
A → B : {Na, A}Kb            ❌  ATTACK FOUND
B → A : {Na, Nb}Ka           Type  : MITM + Authentication Violation
A → B : {Nb}Kb               Trace : Step 1: A → E(B) : {Na,A}Ke
                                      Step 2: E(A) → B : {Na,A}Kb ...
                             Why   : "The attacker E intercepts A's
                                      first message and starts a
                                      parallel session with B..."
                             Fix   : Add B's identity to Message 2
                             PQC   : ⚠️ Public-key encryption is
                                      broken by Shor's algorithm.
                                      Replace with ML-KEM (FIPS 203)
```

---

## Core Novelty

No existing tool combines all three of:

| Feature | Scyther | ProVerif | Tamarin | **QuantumScyther AI** |
|---------|---------|----------|---------|----------------------|
| LaTeX notation input | ❌ | ❌ | ❌ | ✅ |
| Plain English explanation | ❌ | ❌ | ❌ | ✅ |
| Post-Quantum awareness | ❌ | ❌ | ❌ | ✅ |
| No specialized language needed | ❌ | ❌ | ❌ | ✅ |

---

## Architecture — Neuro-Symbolic Hybrid

```
         User Input (LaTeX / YAML)
                   │
    ┌──────────────▼──────────────┐
    │   Layer 3a: LLM Translation │  ← GPT-4o / Claude (few-shot)
    │   LaTeX → Protocol AST      │    Language task: ambiguous notation
    └──────────────┬──────────────┘
                   │
    ┌──────────────▼──────────────┐
    │   Layer 4: Engine           │  ← Pure Python, deterministic
    │   ┌─────────────────────┐   │
    │   │ Term Algebra        │   │    Probabilistic models cannot
    │   │ Dolev-Yao Model     │   │    guarantee logical soundness.
    │   │ Bounded BFS (2 ses) │   │    The engine is the only thing
    │   │ Property Checkers   │   │    that makes security decisions.
    │   └─────────────────────┘   │
    └──────────────┬──────────────┘
                   │
    ┌──────────────▼──────────────┐
    │   Layer 3b: LLM Explanation │  ← GPT-4o / Claude
    │   Attack trace → English    │    Explanation grounded in engine
    │   + PQC fix suggestions     │    output — not independently generated
    └──────────────┬──────────────┘
                   │
    ┌──────────────▼──────────────┐
    │   Layer 5: PQC Flagging     │  ← Deterministic lookup table
    │   Primitive → Quantum risk  │    RSA/ECDH → Shor → ML-KEM
    │   → NIST replacement        │    AES-128 → Grover → AES-256
    └──────────────┬──────────────┘
                   │
    ┌──────────────▼──────────────┐
    │   FastAPI + Streamlit UI    │
    └─────────────────────────────┘
```

**Rule:** LLM handles language. Engine handles logic. Never the other way around.

---

## Attacks Detected

| Attack | How the engine detects it |
|--------|--------------------------|
| MITM | Attacker can complete sessions with both A and B simultaneously |
| Replay | A message from session N is accepted in session M |
| Reflection | A message is sent back to its original sender |
| UKS | A and B agree on key value but disagree on partner identity |
| Secrecy Violation | A secret term is derivable by the attacker |
| Authentication Violation | Responder's run has no matching initiator run |

---

## Project Structure

```
cryptographic_protocol_attack_detection/
│
├── engine/                    ← Custom Dolev-Yao verification engine
│   ├── terms.py               ← Term algebra (Atom, Encrypt, Hash, DH...)
│   ├── dolev_yao.py           ← Attacker knowledge + deduction closure
│   ├── protocol.py            ← Protocol state machine (roles, sessions)
│   ├── explorer.py            ← Bounded BFS model checker
│   ├── checkers.py            ← 6 property checkers
│   ├── benchmark.py           ← Benchmark validation (≥85% target)
│   └── pqc/
│       └── pqc_checker.py     ← Post-quantum primitive flagging
│
├── ai/                        ← LLM integration (language tasks only)
│   ├── latex_parser.py        ← LaTeX → Protocol AST (few-shot)
│   └── explainer.py           ← Attack trace → English + fix suggestion
│
├── extraction/                ← Benchmark dataset pipeline (complete)
│   ├── annotation_schema.py
│   ├── equation_extractor.py
│   ├── protocol_parser.py
│   ├── attack_extractor.py
│   └── build_dataset.py
│
├── data/
│   ├── raw/                   ← 6 verified paper records
│   └── versions/              ← dataset_v0.csv / .json / .xlsx
│
├── api/                       ← FastAPI backend
├── frontend/                  ← Streamlit UI
├── tests/                     ← 104+ tests
├── docs/
│
├── analyze.py                 ← Interactive CLI demo (run this now)
├── PROJECT_PLAN.md
├── README.md
├── PQC_GUIDE.md               ← Post-quantum primitive reference
├── ATTACK_TAXONOMY.md
├── DATA_DICTIONARY.md
├── config.yaml
└── requirements.txt
```

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Try the interactive CLI demo (works right now, no API key needed)
```bash
python analyze.py
```
Type `example` → pick `1` → type `analyze` to see the NSPK MITM breakdown.

### 3. Run tests
```bash
pytest tests/ -v
```
Expected: **104 passed**

### 4. Regenerate the benchmark dataset
```bash
python extraction/build_dataset.py
```

---

## Current Status

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Project setup, documentation, architecture | ✅ Complete |
| 1 | Benchmark dataset (6 protocols, 104 tests) | ✅ Complete |
| 2 | Custom Dolev-Yao verification engine | 🔄 In progress |
| 3 | LLM integration (LaTeX parser + explainer) | ⬜ Pending |
| 4 | PQC flagging (NIST FIPS 203/204/205) | ⬜ Pending |
| 5 | FastAPI + Streamlit frontend | ⬜ Pending |
| 6 | Benchmark validation (≥85% target) + polish | ⬜ Pending |

---

## Benchmark Dataset (Phase 1)

6 verified protocol records. Every equation and attack trace is traced to its source paper.

| ID | Protocol | Attack | Source Paper |
|----|----------|--------|-------------|
| paper_001 | Needham-Schroeder PKP | MITM | Needham-Schroeder 1978 + Lowe 1996 |
| paper_001b | NSL (Lowe fix) | None (secure) | Lowe 1996 |
| paper_002 | NSSK | Replay | NS 1978 + Denning-Sacco 1981 |
| paper_003 | ISO 9798-2 style | Reflection | Syverson 1994 |
| paper_004 | STS Protocol | UKS | Blake-Wilson & Menezes 1999 |
| paper_005 | MQV Protocol | KCI | Blake-Wilson et al. 1997 |

---

## Post-Quantum Awareness

QuantumScyther AI flags primitives that are broken or weakened by quantum computers and maps them to NIST-standardised replacements:

| Primitive in Protocol | Quantum Threat | NIST Replacement |
|----------------------|---------------|-----------------|
| RSA | Shor's algorithm — broken | ML-KEM (FIPS 203) |
| Diffie-Hellman | Shor's algorithm — broken | ML-KEM (FIPS 203) |
| ECDH / ECC | Shor's algorithm — broken | ML-KEM (FIPS 203) |
| Digital signatures (RSA/ECDSA) | Shor's algorithm — broken | ML-DSA (FIPS 204) |
| AES-128 | Grover's algorithm — weakened | AES-256 |
| SHA-256 | Grover's algorithm — weakened | SHA-384 / SHA-512 |

See `PQC_GUIDE.md` for the full reference.

---

## Honest Disclaimer

QuantumScyther AI is **not** a replacement for Scyther, ProVerif, or Tamarin in formal verification research. It trades completeness (unbounded sessions) and theorem-proven soundness for **accessibility** (LaTeX input, English output) and **PQC awareness**. At ≥85% accuracy with 2-session bounds, it is a practical screening and pedagogical tool, not a proof-of-security tool.

---

## References

1. Dolev, D. & Yao, A. (1983). On the Security of Public Key Protocols. *IEEE Trans. Information Theory.*
2. Needham, R.M. & Schroeder, M.D. (1978). Using Encryption for Authentication. *CACM 21(12).*
3. Lowe, G. (1996). Breaking and Fixing the Needham-Schroeder Protocol. *TACAS, LNCS 1055.*
4. Denning, D.E. & Sacco, G.M. (1981). Timestamps in Key Distribution Protocols. *CACM 24(8).*
5. Blake-Wilson, S. & Menezes, A. (1999). Unknown Key-Share Attacks on STS. *PKC, LNCS 1560.*
6. Blake-Wilson, S., Johnson, D. & Menezes, A. (1997). Key Agreement Protocols and their Security Analysis. *IMA, LNCS 1355.*
7. Cremers, C. (2008). The Scyther Tool. *CAV.*
8. NIST (2024). FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA).
