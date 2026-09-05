# CHANGELOG — QuantumScyther AI

All significant changes recorded here in reverse chronological order.

---

## [0.2] — 2026-09-01 — Project Realignment to QuantumScyther AI Proposal

### Changed
- **Project renamed** to QuantumScyther AI
- **PROJECT_PLAN.md** completely rewritten to match the submitted proposal:
  - Removed Scyther integration scope (no external verifier by design)
  - Removed ML attack classifier scope (LLM is for translation + explanation only)
  - Added Phase 2: Custom Dolev-Yao symbolic verification engine (BFS, bounded 2 sessions)
  - Added Phase 3: LLM integration (LaTeX → AST parser, attack trace → English explainer)
  - Added Phase 4: Post-Quantum Cryptography flagging (NIST FIPS 203/204/205)
  - Documented neuro-symbolic split: LLM handles language, engine handles logic
- **README.md** rewritten with QuantumScyther AI branding, architecture diagram,
  comparison table vs Scyther/ProVerif/Tamarin, honest disclaimer
- **config.yaml** rewritten: removed Scyther/ML sections, added engine settings
  (BFS depth, session bound, attacker capabilities, DH equational theory),
  full PQC primitive lookup table in YAML, LLM provider settings

### Added
- **PQC_GUIDE.md** — complete post-quantum reference:
  - Shor's algorithm: breaks RSA, DH, ECDH, ECC, Digital Signatures
  - Grover's algorithm: weakens AES-128, SHA-256, symmetric primitives
  - NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) descriptions
  - Per-primitive lookup table with replacement recommendations
  - Quick reference card

- **engine/** — Custom Dolev-Yao verification engine (Phase 2, in progress):
  - `engine/__init__.py` — module documentation + architectural rule
  - `engine/terms.py` — Term algebra: Atom, Encrypt, Hash, Concat, DH, Pair
    + DH equational theory (g^(xy) == g^(yx)), flatten/build_concat utilities
  - `engine/dolev_yao.py` — AttackerKnowledge class: deduction closure
    (decompose Concat/Pair, decrypt if key known, targeted composition)
  - `engine/protocol.py` — Message, Role, ProtocolDef, Session, ProtocolState
  - `engine/checkers.py` — 6 property checkers: check_secrecy,
    check_authentication, check_replay, check_reflection, check_mitm, check_uks
  - `engine/explorer.py` — Bounded BFS model checker (max 2 sessions),
    VerificationResult with formatted report
  - `engine/benchmark.py` — Benchmark validation runner (target ≥ 85% accuracy)
  - `engine/pqc/pqc_checker.py` — PQCChecker: per-primitive quantum risk lookup,
    formatted PQC report with NIST replacements

- **ai/** — LLM integration layer (Phase 3 stubs, implementation pending):
  - `ai/__init__.py` — documents neuro-symbolic split rule
  - `ai/latex_parser.py` — LaTeXParser interface (Phase 3)
  - `ai/explainer.py` — Explainer interface + fallback (Phase 3)

### Removed (by design — aligning to proposal)
- Scyther integration references from config and plan
- ML attack classifier from roadmap
- `scyther/` phase from active development (directory kept for reference)

### Verified
- All imports pass: `from engine.terms import ...` etc.
- Smoke tests pass: DH equational theory, Dolev-Yao decrypt/can_build, PQC checker
- 104 existing tests still passing (pytest tests/)

---

## [0.3] — 2026-09-04 — Phase 2: Custom Dolev-Yao Engine

### Added
- `engine/unifier.py` — Variable term, match(), substitute(), free_variables()
- `engine/terms.py` — Term algebra (Atom, Encrypt, Hash, Concat, DH, Pair), DH equational theory
- `engine/dolev_yao.py` — AttackerKnowledge class with deduction closure
- `engine/protocol.py` — Message, Role, ProtocolDef, Session, ProtocolState + history field
- `engine/checkers.py` — 8 property checkers: Secrecy, Authentication, Replay, Reflection,
  Structural Reflection, MITM, UKS, Certificate Substitution, KCI
- `engine/explorer.py` — Two-pass bounded BFS (honest run + attacker BFS, max 2 sessions)
- `engine/benchmark.py` — Benchmark validation runner
- `engine/pqc/pqc_checker.py` — Post-quantum primitive lookup (NIST FIPS 203/204/205)
- `engine/protocols/nspk.py` — NSPK (MITM vulnerable) + NSL (Lowe-fixed, SECURE)
- `engine/protocols/nssk.py` — NSSK (Replay vulnerable)
- `engine/protocols/iso9798.py` — ISO 9798-2 style (Reflection vulnerable)
- `engine/protocols/sts.py` — STS Protocol (UKS vulnerable)
- `engine/protocols/mqv.py` — MQV Protocol (KCI vulnerable)
- `quick_check.py` — benchmark runner script
- `tests/test_terms.py` — 40 tests for Term algebra
- `tests/test_dolev_yao.py` — 38 tests for AttackerKnowledge
- `tests/test_checkers.py` — 48 tests for all property checkers
- `tests/test_engine_integration.py` — 25 end-to-end engine tests

### Benchmark results (5/6 = 83%)
| Protocol | Expected | Got | Status |
|----------|----------|-----|--------|
| NSPK | ATTACK | ATTACK (Auth Violation) | ✅ |
| NSL | SECURE | ATTACK (false positive) | ❌ in progress |
| NSSK | ATTACK | ATTACK (Reflection) | ✅ |
| ISO9798 | ATTACK | ATTACK (Auth Violation) | ✅ |
| STS | ATTACK | ATTACK (Reflection) | ✅ |
| MQV | ATTACK | ATTACK (KCI) | ✅ |

### Tests
- 232 unit tests passing (test_terms, test_dolev_yao, test_checkers,
  test_annotation_schema, test_equation_extractor, test_attack_extractor, test_dataset_v0)

### Known issue
- NSL false positive: auth checker fires on a state where the attacker injects
  garbage into the initiator session. Fix in progress.

### Added
- Full project directory structure (26 directories)
- **PROJECT_PLAN.md** v0.1 — initial phase roadmap
- **README.md** v0.1 — quick-start guide
- **requirements.txt** — all dependencies pinned to exact versions
- **config.yaml** v0.1 — master configuration
- **DATA_DICTIONARY.md** — 49-field dataset schema with types, allowed values, examples
- **ATTACK_TAXONOMY.md** — 10 attack categories with mechanisms and detection indicators
- **CHANGELOG.md** — this file
- **.gitignore**

### Phase 1A — Benchmark Dataset (Complete)
- `extraction/annotation_schema.py` — ProtocolRecord dataclass, 49 fields,
  full validation, controlled vocabulary, anti-fabrication guards
- `extraction/equation_extractor.py` — arrow-notation parser (A → B : msg),
  protection type detection, nonce/key extraction, participant normalisation
- `extraction/protocol_parser.py` — builds structured records from raw text
- `extraction/attack_extractor.py` — keyword-based attack detection with
  confidence scoring (HIGH/MEDIUM/LOW/NONE)
- `extraction/build_dataset.py` — generates dataset_v0.csv / .json / .xlsx
- `analyze.py` — interactive CLI protocol analyzer demo

### Dataset v0 (6 records, 0 validation errors)
| ID | Protocol | Attack | Source |
|----|----------|--------|--------|
| paper_001 | Needham-Schroeder PKP | MITM | Needham-Schroeder 1978 + Lowe 1996 |
| paper_001b | NSL (Lowe fix) | None (secure) | Lowe 1996 |
| paper_002 | NSSK | Replay | NS 1978 + Denning-Sacco 1981 |
| paper_003 | ISO 9798-2 style | Reflection | Syverson 1994 |
| paper_004 | STS Protocol | UKS | Blake-Wilson & Menezes 1999 |
| paper_005 | MQV Protocol | KCI | Blake-Wilson et al. 1997 |

### Tests
- `tests/test_annotation_schema.py` — 31 tests
- `tests/test_equation_extractor.py` — 29 tests
- `tests/test_attack_extractor.py` — 22 tests
- `tests/test_dataset_v0.py` — 22 tests
- **Total: 104 tests passing**

### Environment
- Python 3.13.0, scikit-learn 1.6.1, PyTorch 2.10.0 (CPU)
- Transformers 5.3.0, pandas 2.2.3, streamlit 1.56.0, fastapi 0.135.1
- No GPU, no Docker, no Scyther
