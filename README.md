# Cryptographic Protocol Attack Detection System

**B.Tech Minor Semester Project**  
**Domain:** Cryptography · Machine Learning · Formal Verification  
**Status:** Phase 0 — Project Setup Complete

---

## What This Project Does

This system analyzes cryptographic authentication and key-exchange protocols to identify and classify security attacks. It combines:

1. **Dataset extraction** from academic research papers
2. **Machine learning** to predict attack types from protocol representations
3. **Formal verification** via Scyther (when available) to prove or disprove security properties
4. **A user-facing tool** where you can input a protocol and receive a full security analysis

---

## Attack Categories Supported

| ID | Attack Type | Description |
|----|------------|-------------|
| 1 | MITM | Man-in-the-Middle |
| 2 | Replay | Replay Attack |
| 3 | Reflection | Reflection Attack |
| 4 | Impersonation | Impersonation Attack |
| 5 | UKS | Unknown Key-Share |
| 6 | Secrecy_Violation | Secrecy property broken |
| 7 | Authentication_Violation | Authentication claim fails |
| 8 | Session_Key_Compromise | Session key revealed to attacker |
| 9 | KCI | Key-Compromise Impersonation |
| 10 | Forward_Secrecy_Violation | Past sessions broken by key compromise |

---

## Project Pipeline

```
Research Papers
      ↓
Protocol Dataset  (data/)
      ↓
Feature Extraction  (preprocessing/)
      ↓
ML Model Training  (models/)
      ↓
Attack Classification
      ↓
Scyther Formal Verification  (scyther/)
      ↓
User-Facing Analysis Tool  (frontend/ + api/)
```

---

## Directory Structure

```
cryptographic_protocol_attack_detection/
│
├── data/
│   ├── raw/               ← Original extracted records (never overwritten)
│   ├── processed/         ← Cleaned, normalized records
│   ├── annotations/       ← Human review files
│   ├── splits/            ← Train / validation / test splits
│   └── versions/          ← Versioned dataset snapshots (v0, v1, v2 ...)
│
├── papers/
│   ├── metadata/          ← Paper metadata JSON files
│   └── sources/           ← Paper PDFs or references
│
├── extraction/
│   ├── annotation_schema.py    ← Defines dataset fields and validation rules
│   ├── equation_extractor.py   ← Detects cryptographic equations in text
│   ├── protocol_parser.py      ← Parses message flows (A → B : msg)
│   ├── attack_extractor.py     ← Detects attack descriptions and traces
│   └── __init__.py
│
├── preprocessing/
│   ├── normalize_equations.py  ← Standardizes equation notation
│   ├── normalize_messages.py   ← Standardizes message flow representation
│   └── build_features.py       ← Encodes features for ML models
│
├── models/
│   ├── baseline/          ← TF-IDF + Logistic Regression / Random Forest / SVM
│   ├── training/          ← Training scripts
│   ├── evaluation/        ← Evaluation scripts and reports
│   └── saved_models/      ← Serialized trained models (.pkl / .pt)
│
├── scyther/
│   ├── models/            ← Generated .spdl protocol files
│   ├── parser/            ← Parses Scyther output
│   ├── verifier/          ← Scyther wrapper (runs Scyther if available)
│   └── attack_traces/     ← Extracted Scyther attack traces
│
├── api/                   ← FastAPI backend
├── frontend/              ← Streamlit UI
├── notebooks/             ← Jupyter notebooks for exploration
├── tests/                 ← Unit tests and integration tests
├── docs/                  ← Documentation (Scyther guide, etc.)
│
├── requirements.txt
├── config.yaml
├── PROJECT_PLAN.md
├── DATA_DICTIONARY.md
├── ATTACK_TAXONOMY.md
├── DATASET_GUIDE.md       ← (created in Phase 1)
├── MODEL_GUIDE.md         ← (created in Phase 3)
├── SCYTHER_GUIDE.md       ← (created in Phase 4)
└── EXPERIMENTS.md         ← (created in Phase 6)
```

---

## How to Run (Quick Start)

### Prerequisites

- Python 3.10+ (tested on 3.13.0)
- Install dependencies:

```bash
pip install -r requirements.txt
```

### Phase 1 — Build the Dataset

```bash
# Process a single paper
python extraction/protocol_parser.py --input papers/sources/paper_001.pdf

# Run the full extraction pipeline on all papers
python extraction/run_pipeline.py

# Review and annotate extracted data
python extraction/annotation_tool.py
```

### Phase 2 — Preprocess the Dataset

```bash
python preprocessing/build_features.py --input data/processed/dataset_v0.json --output data/splits/
```

### Phase 3 — Train Models

```bash
# Train baseline binary classifier
python models/training/train_baseline.py --task binary

# Train baseline multi-class classifier
python models/training/train_baseline.py --task multiclass
```

### Phase 4 — Run Scyther (requires Scyther installation)

```bash
# Convert a protocol JSON to Scyther format
python scyther/parser/protocol_to_scyther.py --input data/processed/protocol.json --output scyther/models/protocol.spdl

# Run Scyther verification
python scyther/verifier/run_scyther.py --input scyther/models/protocol.spdl
```

### Phase 5 — Run the UI

```bash
# Start the FastAPI backend
uvicorn api.main:app --reload --port 8000

# Start the Streamlit frontend (in a separate terminal)
streamlit run frontend/app.py
```

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Environment

| Component | Version |
|-----------|---------|
| Python | 3.13.0 |
| scikit-learn | 1.6.1 |
| PyTorch | 2.10.0 (CPU) |
| Transformers | 5.3.0 |
| sentence-transformers | 5.3.0 |
| pandas | 2.2.3 |
| streamlit | 1.56.0 |
| fastapi | 0.135.1 |

**Note:** No GPU required. All models are designed to run on CPU.  
**Note:** Scyther is not yet installed. The system will generate `.spdl` files but cannot run formal verification until Scyther is installed. See `docs/scyther_basics.md` for installation instructions (created in Phase 4).

---

## Important Rules

- **No fabricated data.** Every dataset entry is traceable to its source paper and page number.
- **No simulated Scyther output.** If Scyther is not installed, the system says so explicitly.
- **Dataset before model.** The ML model is only trained after the dataset is manually verified.
- **Paper-level splits.** Train/test split is done by `paper_id`, not randomly by row.

---

## Dataset

The dataset is built from academic research papers. Each record contains:

- Protocol name, participants, cryptographic primitives
- Original equations (as written in the paper)
- Normalized machine-readable message flow
- Attacker model and capabilities
- Attack name, category, and trace
- Security property violated
- Source paper, page number, and link

See `DATA_DICTIONARY.md` for full field descriptions.

---

## Attack Taxonomy

See `ATTACK_TAXONOMY.md` for the full taxonomy of attacks, definitions, and examples.

---

## License

This project is for academic use (B.Tech Minor Project). All dataset entries cite their original research paper sources.
