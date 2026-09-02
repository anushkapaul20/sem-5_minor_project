# PROJECT PLAN — Cryptographic Protocol Attack Detection System

**Project:** B.Tech Minor Semester Project  
**Version:** 0.1  
**Last Updated:** 2026-09-01  
**Status:** Phase 0 Complete — Awaiting Phase 1 Confirmation

---

## 1. Project Goal

Build an end-to-end research-grade system that:

1. Ingests research papers on cryptographic authentication and key-exchange protocols.
2. Extracts structured protocol representations (equations, message flows, participants, primitives).
3. Labels each protocol with known attack types from a controlled taxonomy.
4. Trains ML models to classify attacks from protocol representations.
5. Integrates with (or wraps) Scyther for formal protocol verification.
6. Exposes a user-facing tool where a user can input a protocol and receive both ML-based attack prediction and formal verification results.

---

## 2. System Architecture Overview

```
Research Papers (PDF / text)
        │
        ▼
┌───────────────────┐
│  Paper Processing │  ← extraction/
│  Pipeline         │    equation_extractor.py
│                   │    protocol_parser.py
│                   │    attack_extractor.py
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Structured       │  ← data/raw/  →  data/processed/
│  Dataset          │    dataset_v0.csv / dataset_v0.json
│  (with labels)    │    human-verified via annotation workflow
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Preprocessing    │  ← preprocessing/
│  Pipeline         │    normalize_equations.py
│                   │    normalize_messages.py
│                   │    build_features.py
└────────┬──────────┘
         │
         ▼
┌─────────────────────────────────┐
│         ML Models               │  ← models/
│                                 │
│  Model A: Binary Classification │    baseline/  →  training/
│  (attack_present: 0 or 1)       │    evaluation/  →  saved_models/
│                                 │
│  Model B: Multi-class/label     │
│  (attack category)              │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  Scyther Integration            │  ← scyther/
│                                 │
│  If Scyther installed:          │    parser/
│    → Run formal verification    │    verifier/
│  If not installed:              │    models/
│    → Generate .spdl model only  │    attack_traces/
│    → Document for manual run    │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  Result Analyzer                │
│  (combine ML + formal results)  │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  User-Facing Tool               │  ← frontend/  +  api/
│  (Streamlit UI + FastAPI)       │
│  Shows:                         │
│    - Attack prediction (ML)     │
│    - Formal result (Scyther)    │
│    - Attack trace               │
│    - Violated property          │
│    - Explanation                │
└─────────────────────────────────┘
```

---

## 3. Phases and Milestones

### PHASE 0 — Project Setup and Architecture
**Goal:** Clean environment, documented structure, no code yet.

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 0.1 | Environment inspection report | ✅ Done |
| 0.2 | Directory structure created | ✅ Done |
| 0.3 | PROJECT_PLAN.md | ✅ Done |
| 0.4 | README.md | ✅ Done |
| 0.5 | requirements.txt | ✅ Done |
| 0.6 | config.yaml | ✅ Done |
| 0.7 | DATA_DICTIONARY.md | ✅ Done |
| 0.8 | ATTACK_TAXONOMY.md | ✅ Done |

---

### PHASE 1A — Small Dataset (5 Papers)
**Goal:** Prove the extraction pipeline works on 5 carefully chosen papers before scaling.

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 1A.1 | annotation_schema.py — defines all dataset fields | ⬜ Pending |
| 1A.2 | equation_extractor.py — regex + rule-based equation detector | ⬜ Pending |
| 1A.3 | protocol_parser.py — parses message flows | ⬜ Pending |
| 1A.4 | attack_extractor.py — detects attack descriptions | ⬜ Pending |
| 1A.5 | 5 papers manually processed → raw JSON records | ⬜ Pending |
| 1A.6 | dataset_v0.csv + dataset_v0.json created | ⬜ Pending |
| 1A.7 | dataset_review_v0.xlsx for human verification | ⬜ Pending |
| 1A.8 | Unit tests for parsers | ⬜ Pending |

**Target papers (one per attack type):**
- Paper 1: MITM attack
- Paper 2: Replay attack
- Paper 3: Reflection attack
- Paper 4: UKS attack
- Paper 5: KCI attack

**Rule:** No fabricated data. Every field traceable to its source page.

---

### PHASE 1B — Full Dataset Pipeline
**Goal:** Scale to 20–50+ papers after 5-paper validation.

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 1B.1 | Batch paper processing pipeline | ⬜ Pending |
| 1B.2 | dataset_v1 with 20+ papers | ⬜ Pending |
| 1B.3 | Human verification workflow complete | ⬜ Pending |
| 1B.4 | dataset_v1 quality report | ⬜ Pending |

---

### PHASE 2 — Data Preprocessing
**Goal:** Clean, normalize, encode the dataset for ML consumption.

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 2.1 | normalize_equations.py | ⬜ Pending |
| 2.2 | normalize_messages.py | ⬜ Pending |
| 2.3 | build_features.py | ⬜ Pending |
| 2.4 | Paper-level train/val/test split | ⬜ Pending |
| 2.5 | Class imbalance analysis | ⬜ Pending |
| 2.6 | Preprocessing unit tests | ⬜ Pending |

**Important:** Split by `paper_id`, not by row. No data leakage.

---

### PHASE 3 — Baseline ML Models
**Goal:** Working, evaluated baseline before any complex architecture.

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 3.1 | Model A: Binary classifier (TF-IDF + Logistic Regression) | ⬜ Pending |
| 3.2 | Model B: Multi-class classifier (TF-IDF + Random Forest) | ⬜ Pending |
| 3.3 | Evaluation report (accuracy, precision, recall, F1, confusion matrix) | ⬜ Pending |
| 3.4 | Class imbalance handling (if needed) | ⬜ Pending |

---

### PHASE 3B — Improved Models
**Goal:** Beat baseline with better protocol representations.

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 3B.1 | Sentence-transformer embeddings | ⬜ Pending |
| 3B.2 | Improved classifier on embeddings | ⬜ Pending |
| 3B.3 | Comparison report: baseline vs improved | ⬜ Pending |

**Note:** No deep learning until dataset is large enough. Start with CPU-friendly models.

---

### PHASE 4 — Scyther Integration
**Goal:** Produce Scyther-compatible protocol files; run Scyther if available.

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 4.1 | docs/scyther_basics.md | ⬜ Pending |
| 4.2 | protocol_to_scyther.py converter | ⬜ Pending |
| 4.3 | Scyther wrapper (scyther/verifier/) | ⬜ Pending |
| 4.4 | Test on 3 protocols | ⬜ Pending |

**Current status:** Scyther NOT installed. Will build wrapper + converter so Scyther can be plugged in once installed. Will never fake formal verification output.

---

### PHASE 5 — User-Facing Tool
**Goal:** Streamlit UI + FastAPI backend accepting protocol input.

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 5.1 | FastAPI protocol input endpoint | ⬜ Pending |
| 5.2 | Streamlit frontend | ⬜ Pending |
| 5.3 | ML prediction displayed | ⬜ Pending |
| 5.4 | Scyther result displayed (or not-available notice) | ⬜ Pending |
| 5.5 | Explainability output | ⬜ Pending |

---

### PHASE 6 — Integration and Final Report
**Goal:** Combined ML + Scyther analysis in one report.

| Milestone | Deliverable | Status |
|-----------|------------|--------|
| 6.1 | Result analyzer module | ⬜ Pending |
| 6.2 | Final report generator | ⬜ Pending |
| 6.3 | End-to-end integration test | ⬜ Pending |
| 6.4 | EXPERIMENTS.md | ⬜ Pending |

---

## 4. Environment Summary

| Component | Status | Version / Notes |
|-----------|--------|----------------|
| Python | ✅ Available | 3.13.0 |
| scikit-learn | ✅ Available | 1.6.1 |
| PyTorch | ✅ Available | 2.10.0+cpu (CPU only) |
| Transformers | ✅ Available | 5.3.0 |
| sentence-transformers | ✅ Available | 5.3.0 |
| pandas | ✅ Available | 2.2.3 |
| numpy | ✅ Available | 2.2.2 |
| pypdf | ✅ Available | 6.13.3 |
| streamlit | ✅ Available | 1.56.0 |
| fastapi | ✅ Available | 0.135.1 |
| Docker | ❌ Not installed | Not required for Phase 0–3 |
| GPU / CUDA | ❌ Not available | CPU-only — use lightweight models |
| Scyther | ❌ Not installed | Will build wrapper; install later |
| Storage | ✅ Sufficient | 166 GB free on C: |

---

## 5. Key Design Decisions

### Decision 1: No GPU
**Implication:** Avoid large transformer fine-tuning (e.g., training GPT-2). Use:
- Frozen sentence-transformer embeddings (inference only)
- scikit-learn classifiers on top of embeddings
- TF-IDF + classical ML as baseline

### Decision 2: Scyther not installed
**Implication:** Build the converter and wrapper architecture first. Never simulate Scyther output. When Scyther is installed, plug it in.

### Decision 3: Dataset before model
**Implication:** No ML code until dataset_v0 is validated. Building on fabricated data is worse than having no model.

### Decision 4: Paper-level splits
**Implication:** A protocol that appears in paper_001 must not appear in both train and test. Split by paper_id.

### Decision 5: Two equation representations
**Implication:** Always preserve `original_equations` (as written in the paper). `normalized_equations` is the machine-readable version. Never overwrite original.

---

## 6. Anti-Fabrication Policy

This project is built on research papers. The following rules are **non-negotiable**:

- Every equation must be traced to a page in a specific paper.
- Every attack trace must come from the paper or from Scyther output.
- If a field cannot be verified, it is marked `REQUIRES_MANUAL_VERIFICATION`, not guessed.
- `extraction_status` must be one of: `AUTO_EXTRACTED`, `HUMAN_VERIFIED`, `REQUIRES_REVIEW`.
- Dataset rows are never fabricated to inflate numbers.

---

## 7. File Naming Conventions

| Type | Convention | Example |
|------|-----------|---------|
| Dataset versions | `dataset_v{N}.csv` | `dataset_v0.csv` |
| Raw paper records | `paper_{id}_raw.json` | `paper_001_raw.json` |
| Scyther models | `{protocol_name}.spdl` | `needham_schroeder.spdl` |
| Saved ML models | `model_{type}_{version}.pkl` | `model_binary_v0.pkl` |
| Notebooks | `{phase}_{topic}.ipynb` | `phase1_exploration.ipynb` |

---

## 8. Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.1 | 2026-09-01 | Initial project setup, Phase 0 complete |
