# PROJECT PLAN — QuantumScyther AI

**Project Name:** QuantumScyther AI  
**Subtitle:** AI-Powered Cryptographic Protocol Verification with Post-Quantum Awareness  
**Type:** B.Tech Minor Project — Semester 5  
**Version:** 0.2  
**Last Updated:** 2026-09-01  
**Status:** Phase 0 ✅ Complete | Phase 1 ✅ Complete | Phase 2 🔄 Next

---

## 1. Project Goal

Build **QuantumScyther AI** — a custom cryptographic protocol verification tool that:

1. Accepts protocol specifications in **LaTeX notation** (as written in research papers) or structured **YAML**
2. Parses them using an **LLM** (GPT-4o / Claude) into a structured Protocol AST
3. Verifies them using a **fully custom Dolev-Yao symbolic verification engine** (BFS, bounded to 2 sessions) — no Scyther, ProVerif, or Tamarin
4. Detects vulnerabilities: **MITM, Replay, Reflection, UKS, Secrecy leaks, Authentication failures**
5. Uses an **LLM** to explain detected attacks in plain English and suggest fixes
6. **Flags primitives vulnerable to quantum computing** (Shor/Grover) and maps them to **NIST PQC replacements** (FIPS 203/204/205)

**Core novelty:** No existing tool combines (a) LaTeX-notation input, (b) plain-English attack explanation, and (c) Post-Quantum vulnerability flagging in a single verification pipeline.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────┐
│            Layer 1 — User Interface              │
│   Streamlit web frontend: input, visualization,  │
│   reports, attack sequence diagrams              │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│            Layer 2 — Backend API                 │
│   FastAPI: REST endpoints, pipeline orchestration│
└──────────┬──────────────────────┬───────────────┘
           │                      │
┌──────────▼──────────┐ ┌─────────▼──────────────┐
│  Layer 3a           │ │  Layer 3b               │
│  LLM Translation    │ │  LLM Explanation        │
│                     │ │                         │
│  LaTeX / YAML       │ │  Attack Trace           │
│      ↓              │ │      ↓                  │
│  Protocol AST       │ │  Plain English          │
│  (few-shot GPT-4o)  │ │  + PQC fix suggestions  │
└──────────┬──────────┘ └─────────────────────────┘
           │
┌──────────▼──────────────────────────────────────┐
│            Layer 4 — Verification Engine         │
│                   engine/                        │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │  Term Algebra                            │   │
│  │  (Message, Encrypt, Hash, DH, Concat)    │   │
│  └──────────────────┬───────────────────────┘   │
│                     │                            │
│  ┌──────────────────▼───────────────────────┐   │
│  │  Dolev-Yao Attacker Model                │   │
│  │  Deduction Closure (what E can derive)   │   │
│  └──────────────────┬───────────────────────┘   │
│                     │                            │
│  ┌──────────────────▼───────────────────────┐   │
│  │  Bounded BFS State Explorer              │   │
│  │  (max 2 concurrent protocol sessions)    │   │
│  └──────────────────┬───────────────────────┘   │
│                     │                            │
│  ┌──────────────────▼───────────────────────┐   │
│  │  Property Checkers                       │   │
│  │  Secrecy | Authentication | Replay       │   │
│  │  Reflection | MITM | UKS                 │   │
│  └──────────────────────────────────────────┘   │
└──────────┬──────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────┐
│            Layer 5 — PQC Flagging                │
│                   engine/pqc/                    │
│                                                  │
│  Classical Primitive → Quantum Threat →          │
│  NIST PQC Replacement                            │
│  (RSA/ECDH → Shor → ML-KEM FIPS 203)            │
│  (AES-128 → Grover → AES-256)                   │
└─────────────────────────────────────────────────┘
```

### Architectural Rule — Neuro-Symbolic Split

| Task | Who does it | Why |
|------|------------|-----|
| Parse LaTeX notation | LLM (GPT-4o / Claude) | Notation is ambiguous, varies by author |
| Detect vulnerabilities | Deterministic engine | Probabilistic models cannot guarantee logical soundness |
| Explain attacks in English | LLM | Natural language generation is LLM's strength |
| PQC flagging | Deterministic lookup table | Exact match against known quantum threats |

**This split is non-negotiable.** The LLM never makes security decisions. The engine never generates natural language.

---

## 3. What We Are NOT Building

To avoid scope confusion:

- ❌ **No Scyther** — no SPDL files, no Scyther wrapper, no Scyther integration
- ❌ **No ProVerif / Tamarin** — no applied pi-calculus, no multiset rewriting
- ❌ **No ML attack classifier** — the engine detects attacks, not a trained model
- ❌ **No unbounded verification** — hard limit of 2 concurrent sessions (BFS)
- ❌ **No proof of security** — this is a screening and pedagogical tool, not a theorem prover

---

## 4. Phases and Milestones

---

### PHASE 0 — Project Setup ✅ COMPLETE

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 0.1 | Environment inspection | ✅ Done |
| 0.2 | Directory structure | ✅ Done |
| 0.3 | PROJECT_PLAN.md | ✅ Done |
| 0.4 | README.md | ✅ Done |
| 0.5 | requirements.txt | ✅ Done |
| 0.6 | config.yaml | ✅ Done |
| 0.7 | DATA_DICTIONARY.md | ✅ Done |
| 0.8 | ATTACK_TAXONOMY.md | ✅ Done |
| 0.9 | PQC_GUIDE.md | ✅ Done |

---

### PHASE 1 — Benchmark Dataset ✅ COMPLETE

**Goal:** Build a validated dataset of known protocols and their attacks. Used to benchmark the engine at ≥ 85% accuracy.

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 1.1 | annotation_schema.py — 49-field ProtocolRecord | ✅ Done |
| 1.2 | equation_extractor.py — arrow-notation parser | ✅ Done |
| 1.3 | protocol_parser.py — structured record builder | ✅ Done |
| 1.4 | attack_extractor.py — keyword detection | ✅ Done |
| 1.5 | build_dataset.py — CSV / JSON / XLSX generator | ✅ Done |
| 1.6 | 6 raw paper records (paper_001 to paper_005 + 001b) | ✅ Done |
| 1.7 | dataset_v0.csv + dataset_v0.json (0 validation errors) | ✅ Done |
| 1.8 | dataset_review_v0.xlsx (human review sheet) | ✅ Done |
| 1.9 | 104 passing unit tests | ✅ Done |

**Papers in dataset_v0:**

| Paper ID | Protocol | Attack Type | Source |
|----------|----------|-------------|--------|
| paper_001 | Needham-Schroeder PKP | MITM | Needham-Schroeder 1978 + Lowe 1996 |
| paper_001b | NSL (Lowe fix) | None (secure) | Lowe 1996 |
| paper_002 | NSSK | Replay | Needham-Schroeder 1978 + Denning-Sacco 1981 |
| paper_003 | ISO 9798-2 style | Reflection | Syverson 1994 |
| paper_004 | STS Protocol | UKS | Blake-Wilson & Menezes 1999 |
| paper_005 | MQV Protocol | KCI | Blake-Wilson et al. 1997 |

**Role of this dataset going forward:** Benchmark validation for the engine. After Phase 2, the engine is run against all 6 records and must detect the correct attack in each.

---

### PHASE 2 — Custom Verification Engine 🔄 NEXT

**Goal:** Build the core symbolic verification engine in Python. This is the heart of the project.

**Target:** ≥ 85% correct detection on the 12–15 benchmark protocols (dataset_v0 + expanded set).

#### 2.1 — Term Algebra  `engine/terms.py`

Define the message term language:

```python
# Everything in the protocol is a Term
Atom("Na")                          # atomic value: nonce, key, identity
Encrypt(payload, key)               # {payload}key
Hash(content)                       # H(content)
Concat(left, right)                 # Na || Nb
DH(base, exponent)                  # g^x
Pair(a, b)                          # (a, b)
```

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 2.1.1 | `engine/terms.py` — Term dataclass hierarchy | ⬜ Pending |
| 2.1.2 | Term equality and unification | ⬜ Pending |
| 2.1.3 | Term decomposition (what attacker can split) | ⬜ Pending |
| 2.1.4 | Unit tests: `tests/test_terms.py` | ⬜ Pending |

#### 2.2 — Dolev-Yao Attacker Model  `engine/dolev_yao.py`

The Dolev-Yao attacker can:
- **Intercept** any message on any channel
- **Send** any message it can construct from its knowledge
- **Decrypt** `{M}K` if it knows `K`
- **Compute** `H(M)` for any `M` it knows
- **Compose** new messages from known components
- **NOT** break encryption if it doesn't know the key

Implement the **deduction closure**: given a set of known terms, compute everything the attacker can derive.

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 2.2.1 | `engine/dolev_yao.py` — attacker knowledge set | ⬜ Pending |
| 2.2.2 | Deduction closure algorithm | ⬜ Pending |
| 2.2.3 | DH special case: `g^(ab) = g^(ba)` hardcoded | ⬜ Pending |
| 2.2.4 | Unit tests: `tests/test_dolev_yao.py` | ⬜ Pending |

#### 2.3 — Protocol State Machine  `engine/protocol.py`

Represent a protocol run as a state machine:
- **Roles:** Initiator, Responder (+ optional Server)
- **State:** current step, knowledge of each role
- **Transitions:** send/receive events
- **Sessions:** support 2 concurrent sessions simultaneously

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 2.3.1 | `engine/protocol.py` — Role, Session, ProtocolState | ⬜ Pending |
| 2.3.2 | Protocol execution (honest run) | ⬜ Pending |
| 2.3.3 | Attacker interleaving (parallel sessions) | ⬜ Pending |
| 2.3.4 | Unit tests: `tests/test_protocol.py` | ⬜ Pending |

#### 2.4 — Bounded BFS Explorer  `engine/explorer.py`

The model checker:
- Explores all reachable states (honest + attacker moves)
- **Hard bound:** 2 concurrent sessions maximum
- **BFS** (breadth-first) to find shortest attack first
- Returns the attack trace if a property is violated

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 2.4.1 | `engine/explorer.py` — BFS state space search | ⬜ Pending |
| 2.4.2 | State deduplication (avoid revisiting same state) | ⬜ Pending |
| 2.4.3 | Timeout / depth limit guard | ⬜ Pending |
| 2.4.4 | Unit tests: `tests/test_explorer.py` | ⬜ Pending |

#### 2.5 — Property Checkers  `engine/checkers.py`

Six checkers, each returning `(violated: bool, attack_trace: list)`:

| Checker | What it verifies |
|---------|-----------------|
| `check_secrecy(term, state)` | Is `term` ever derivable by the attacker? |
| `check_authentication(role, state)` | Does the responder's completed run match an initiator run? |
| `check_replay(state)` | Is any message accepted that was sent in a previous session? |
| `check_reflection(state)` | Is any message sent back to its original sender without modification? |
| `check_mitm(state)` | Can the attacker sit between A and B with both believing they communicate with each other? |
| `check_uks(state)` | Do A and B agree on the key but disagree on partner identity? |

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 2.5.1 | `engine/checkers.py` — all 6 property checkers | ⬜ Pending |
| 2.5.2 | Unit tests per checker: `tests/test_checkers.py` | ⬜ Pending |

#### 2.6 — Benchmark Validation

Run engine on dataset_v0. Target: ≥ 85% correct on known-outcome protocols.

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 2.6.1 | `engine/benchmark.py` — run engine on all dataset records | ⬜ Pending |
| 2.6.2 | Benchmark report: predicted vs expected attack | ⬜ Pending |
| 2.6.3 | Debug and fix deduction rule gaps until ≥ 85% | ⬜ Pending |

---

### PHASE 3 — AI Integration 🔲 Pending

**Goal:** LLM handles language tasks. Engine handles logic. Strict separation.

#### 3.1 — LaTeX → AST Parser  `ai/latex_parser.py`

- Input: LaTeX protocol notation (e.g. `A \rightarrow B : \{N_a, A\}_{K_b}`)
- Method: few-shot prompting (GPT-4o / Claude API)
- Output: validated Protocol AST (same format as `annotation_schema.py`)
- Fallback: manual YAML input if LLM fails or API not available

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 3.1.1 | `ai/latex_parser.py` — few-shot prompt + AST validator | ⬜ Pending |
| 3.1.2 | 5 few-shot examples covering NSPK, NSSK, STS, MQV, DH | ⬜ Pending |
| 3.1.3 | YAML manual input fallback | ⬜ Pending |
| 3.1.4 | Unit tests: `tests/test_latex_parser.py` | ⬜ Pending |

#### 3.2 — Attack Explanation  `ai/explainer.py`

- Input: engine attack trace (structured list of steps)
- Method: single LLM call — trace is the ground truth, LLM only generates language
- Output: plain English paragraph explaining what happened and why
- Also: suggests protocol fix (e.g. "add B's identity to Message 2")

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 3.2.1 | `ai/explainer.py` — explanation prompt + fix suggestion | ⬜ Pending |
| 3.2.2 | Grounding rule: explanation must reference engine trace, not invent new facts | ⬜ Pending |
| 3.2.3 | Unit tests: `tests/test_explainer.py` | ⬜ Pending |

---

### PHASE 4 — PQC Flagging 🔲 Pending

**Goal:** Flag quantum-vulnerable primitives and suggest NIST PQC replacements.

File: `engine/pqc/pqc_checker.py`

| Classical Primitive | Quantum Threat | Impact | NIST PQC Replacement |
|--------------------|---------------|--------|---------------------|
| RSA (any key size) | Shor's algorithm | Broken completely | ML-KEM (FIPS 203) |
| Diffie-Hellman (finite field) | Shor's algorithm | Broken completely | ML-KEM (FIPS 203) |
| ECDH / ECC | Shor's algorithm | Broken completely | ML-KEM (FIPS 203) |
| DSA / ECDSA | Shor's algorithm | Broken completely | ML-DSA (FIPS 204) |
| RSA signatures | Shor's algorithm | Broken completely | SLH-DSA (FIPS 205) |
| AES-128 | Grover's algorithm | Security halved (64-bit) | AES-256 |
| AES-256 | Grover's algorithm | Acceptable (128-bit) | No change needed |
| SHA-256 | Grover's algorithm | Security halved | SHA-384 or SHA-512 |
| SHA-3 | Grover's algorithm | Acceptable | No change needed |
| Hash-based signatures | Minimal | Acceptable | No change needed |

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 4.1 | `engine/pqc/pqc_checker.py` — lookup table + flagging logic | ✅ Done (PQC_GUIDE.md) |
| 4.2 | PQC report section in final output | ⬜ Pending |
| 4.3 | Unit tests: `tests/test_pqc.py` | ⬜ Pending |

---

### PHASE 5 — Frontend and API 🔲 Pending

**Goal:** Streamlit UI + FastAPI backend. User enters a protocol, sees full analysis.

#### Output report shown to user:

```
┌─────────────────────────────────────────────────┐
│  Protocol:        Needham-Schroeder PKP          │
│  Input format:    LaTeX / YAML                   │
├─────────────────────────────────────────────────┤
│  VERIFICATION RESULT                             │
│  ─────────────────                              │
│  ❌  ATTACK FOUND                               │
│                                                  │
│  Attack type:     MITM + Authentication Violation│
│  Violated:        Entity authentication at B     │
├─────────────────────────────────────────────────┤
│  ATTACK TRACE  (engine output)                   │
│  ─────────────                                   │
│  Step 1: A → E(B) : {Na, A}Ke                   │
│  Step 2: E(A) → B : {Na, A}Kb                   │
│  Step 3: B → E(A) : {Na,Nb}Ka   ← intercepted  │
│  Step 4: E(B) → A : {Na,Nb}Ka                   │
│  Step 5: A → E(B) : {Nb}Ke                      │
│  Step 6: E(A) → B : {Nb}Kb                      │
├─────────────────────────────────────────────────┤
│  PLAIN ENGLISH EXPLANATION  (LLM generated)      │
│  ──────────────────────────                      │
│  "The attacker E intercepts A's first message    │
│   and starts a parallel session with B..."       │
│  Fix: Add B's identity to Message 2.             │
├─────────────────────────────────────────────────┤
│  POST-QUANTUM ANALYSIS                           │
│  ─────────────────────                           │
│  ⚠️  RSA/Public-key encryption: VULNERABLE       │
│     Threat: Shor's algorithm breaks RSA          │
│     Replace with: ML-KEM (NIST FIPS 203)         │
└─────────────────────────────────────────────────┘
```

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 5.1 | `api/main.py` — FastAPI endpoints | ⬜ Pending |
| 5.2 | `frontend/app.py` — Streamlit UI | ⬜ Pending |
| 5.3 | Mermaid.js sequence diagram of protocol + attack | ⬜ Pending |
| 5.4 | End-to-end integration test | ⬜ Pending |

---

### PHASE 6 — Polish and Evaluation 🔲 Pending

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 6.1 | EXPERIMENTS.md — full benchmark results | ⬜ Pending |
| 6.2 | Final accuracy report (≥ 85% target) | ⬜ Pending |
| 6.3 | Presentation materials | ⬜ Pending |
| 6.4 | Optional: fine-tuned 7B model for LaTeX parsing (QLoRA) | ⬜ Optional |

---

## 5. Performance Targets

| Parameter | Target |
|-----------|--------|
| Detection accuracy | ≥ 85% on 12–15 benchmark protocols |
| State-space bound | 2 concurrent sessions (hard limit) |
| Verification approach | Bounded Dolev-Yao BFS |
| LLM role | Translation + explanation only |
| Vulnerability detection | Fully deterministic engine |
| External verifier dependency | None |

---

## 6. Environment Summary

| Component | Status | Notes |
|-----------|--------|-------|
| Python | ✅ 3.13.0 | |
| FastAPI | ✅ 0.135.1 | API layer |
| Streamlit | ✅ 1.56.0 | Frontend |
| pandas / numpy | ✅ | Dataset handling |
| pytest | ✅ 9.0.3 | 104 tests passing |
| OpenAI / Anthropic API | ⬜ Key needed | For LaTeX parser + explainer |
| GPU | ❌ Not available | Not needed — engine is pure Python |
| Scyther | ❌ Not used | By design — custom engine replaces it |
| Docker | ❌ Not installed | Not required |

---

## 7. Key Design Decisions

| Decision | Choice | Reason |
|----------|--------|--------|
| No external verifier | Custom BFS engine | Project novelty; no Scyther/ProVerif dependency |
| Session bound | 2 sessions | Prevents state explosion; sufficient for known attacks |
| LLM for translation | GPT-4o few-shot | LaTeX notation is ambiguous; LLM handles variants naturally |
| LLM for explanation only | Never for detection | Probabilistic model cannot guarantee logical soundness |
| PQC via lookup table | Deterministic | Exact match against known quantum threats; no guessing |
| YAML fallback | Always available | System works without LLM API key |
| Benchmark first | Engine validated before UI | Accuracy target verified before user-facing release |

---

## 8. File Structure

```
quantumscyther_ai/   (= cryptographic_protocol_attack_detection/)
│
├── engine/                    ← Phase 2: Custom verification engine
│   ├── terms.py               ← Term algebra
│   ├── dolev_yao.py           ← Attacker model + deduction closure
│   ├── protocol.py            ← Protocol state machine
│   ├── explorer.py            ← Bounded BFS model checker
│   ├── checkers.py            ← 6 property checkers
│   ├── benchmark.py           ← Benchmark validation runner
│   └── pqc/
│       └── pqc_checker.py     ← Post-quantum primitive lookup
│
├── ai/                        ← Phase 3: LLM integration
│   ├── latex_parser.py        ← LaTeX → Protocol AST (few-shot LLM)
│   └── explainer.py           ← Attack trace → English explanation
│
├── extraction/                ← Phase 1: Benchmark dataset (DONE)
│   ├── annotation_schema.py
│   ├── equation_extractor.py
│   ├── protocol_parser.py
│   ├── attack_extractor.py
│   └── build_dataset.py
│
├── data/                      ← Benchmark dataset (DONE)
│   ├── raw/                   ← 6 verified paper records
│   └── versions/              ← dataset_v0.csv / .json / .xlsx
│
├── api/                       ← Phase 5: FastAPI backend
│   └── main.py
│
├── frontend/                  ← Phase 5: Streamlit UI
│   └── app.py
│
├── tests/                     ← 104 tests passing + engine tests
│
├── docs/                      ← Documentation
│
├── analyze.py                 ← Interactive CLI demo (Phase 1 demo)
├── PROJECT_PLAN.md
├── README.md
├── PQC_GUIDE.md
├── ATTACK_TAXONOMY.md
├── DATA_DICTIONARY.md
├── config.yaml
└── requirements.txt
```

---

## 9. What Was Built vs What the Proposal Requires

| Proposal Requirement | Status | Notes |
|---------------------|--------|-------|
| LaTeX / YAML input | ⬜ Phase 3 | Arrow-notation parser exists as fallback |
| Custom Dolev-Yao engine | ⬜ Phase 2 | Starting next |
| Property checkers (6) | ⬜ Phase 2 | |
| NO external verifier | ✅ By design | Scyther removed from scope |
| LLM translation (LaTeX → AST) | ⬜ Phase 3 | |
| LLM explanation (trace → English) | ⬜ Phase 3 | |
| PQC flagging (FIPS 203/204/205) | ⬜ Phase 4 | PQC_GUIDE.md written |
| FastAPI backend | ⬜ Phase 5 | Scaffolded |
| Streamlit frontend | ⬜ Phase 5 | Scaffolded |
| Benchmark dataset (≥12 protocols) | 🔄 6 done | Expanding to 12+ in Phase 2.6 |
| ≥85% detection accuracy | ⬜ Phase 2.6 | Measured after engine built |

---

## 10. Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.1 | 2026-09-01 | Initial setup, Phase 0 complete |
| 0.2 | 2026-09-01 | Realigned to QuantumScyther AI proposal. Removed Scyther/ML-classifier scope. Added custom engine, LLM layer, PQC flagging. Phase 1 marked complete. |
