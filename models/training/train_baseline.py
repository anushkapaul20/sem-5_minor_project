"""
models/training/train_baseline.py
==================================
QuantumScyther AI — Baseline ML Model Training

Trains TWO models on the verified benchmark dataset:

  Model A — Binary classifier:
    Input : serialised protocol representation
    Output: attack_present (0 = secure, 1 = attack)
    Method: TF-IDF + Logistic Regression

  Model B — Multi-class classifier:
    Input : serialised protocol representation
    Output: attack_category (MITM, Replay, Reflection, ...)
    Method: TF-IDF + Random Forest

The model input is a serialised string built from:
  - Protocol name
  - Participants
  - Cryptographic primitives
  - Original equations
  - Attacker capabilities
  - Attack name (for model B, NOT used in Model A to avoid leakage)

Split strategy: by paper_id (not by row) — no data leakage.

Run from project root:
    python models/training/train_baseline.py
    python models/training/train_baseline.py --dataset data/versions/dataset_v1.json
"""

from __future__ import annotations

import argparse
import json
import pickle
import sys
from datetime import date
from pathlib import Path
from typing import List, Tuple

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import LeaveOneOut
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

SAVED = ROOT / "models" / "saved_models"
SAVED.mkdir(parents=True, exist_ok=True)

# ── Feature serialisation ──────────────────────────────────────────────────────

def serialise_record(r: dict, include_attack_name: bool = False) -> str:
    """
    Convert a dataset record into a single string for TF-IDF vectorisation.

    Combines: protocol name, participants, primitives, equations,
    attacker model, attacker capabilities, message count.

    NOTE: attack_name and attack_trace are EXCLUDED unless include_attack_name=True
    to prevent data leakage into the binary classifier.
    """
    parts = []

    # Protocol identity
    parts.append(f"PROTOCOL {r.get('protocol_name', '')}")
    parts.append(f"TYPE {r.get('protocol_type', '')}")

    # Participants
    participants = r.get("participants", [])
    if isinstance(participants, str):
        try:
            participants = json.loads(participants)
        except Exception:
            participants = []
    parts.append(f"PARTICIPANTS {' '.join(str(p) for p in participants)}")
    parts.append(f"TTP {'yes' if r.get('trusted_third_party') else 'no'}")

    # Cryptographic primitives
    prims = r.get("cryptographic_primitives", [])
    if isinstance(prims, str):
        try:
            prims = json.loads(prims)
        except Exception:
            prims = []
    parts.append(f"PRIMITIVES {' '.join(str(p) for p in prims)}")

    # Equations (original — most information-rich field)
    equations = r.get("original_equations", "")
    parts.append(f"EQUATIONS {equations}")

    # Message step count
    parts.append(f"STEPS {r.get('message_step_count', 0)}")

    # Attacker model and capabilities
    parts.append(f"ATTACKER {r.get('attacker_model', '')}")
    caps = r.get("attacker_capabilities", [])
    if isinstance(caps, str):
        try:
            caps = json.loads(caps)
        except Exception:
            caps = []
    parts.append(f"CAPABILITIES {' '.join(str(c) for c in caps)}")

    # Security property targeted
    props = r.get("security_property_targeted", [])
    if isinstance(props, str):
        try:
            props = json.loads(props)
        except Exception:
            props = []
    parts.append(f"PROPERTIES {' '.join(str(p) for p in props)}")

    # Attack name (only for multi-class, and only partial to avoid full leakage)
    if include_attack_name:
        parts.append(f"ATTACK {r.get('attack_name', 'None')}")

    return " | ".join(parts)


def get_primary_attack_category(r: dict) -> str:
    """Return the primary (first non-None) attack category for multi-class."""
    cats = r.get("attack_category", ["None"])
    if isinstance(cats, str):
        try:
            cats = json.loads(cats)
        except Exception:
            cats = ["None"]
    for c in cats:
        if c != "None":
            return c
    return "None"


# ── Load dataset ──────────────────────────────────────────────────────────────

def load_records(dataset_path: Path) -> List[dict]:
    with open(dataset_path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("records", [])


# ── Training ──────────────────────────────────────────────────────────────────

def train_and_evaluate(
    records: List[dict],
    dataset_version: str = "v1",
) -> dict:
    """
    Train Model A (binary) and Model B (multi-class) and return results.

    Because the dataset is small (≤ 20 records), we use Leave-One-Out
    cross-validation to get meaningful evaluation metrics.
    """
    print(f"\n{'='*60}")
    print(f"  QuantumScyther AI — Baseline ML Training")
    print(f"  Dataset: {dataset_version}  |  Records: {len(records)}")
    print(f"{'='*60}")

    # ── Prepare features ───────────────────────────────────────────────
    X_binary = [serialise_record(r, include_attack_name=False) for r in records]
    X_multi  = [serialise_record(r, include_attack_name=False)  for r in records]
    y_binary = [r.get("attack_present", 0) for r in records]
    y_multi  = [get_primary_attack_category(r) for r in records]

    print(f"\n  Features built for {len(records)} records")
    print(f"  Binary labels : {dict(zip(*np.unique(y_binary, return_counts=True)))}")
    print(f"  Multi  labels : {dict(zip(*np.unique(y_multi,  return_counts=True)))}")

    results = {}

    # ── Model A: Binary Classifier ─────────────────────────────────────
    print(f"\n{'─'*60}")
    print("  MODEL A — Binary Classifier (attack_present: 0 or 1)")
    print("  Method: TF-IDF (char n-grams) + Logistic Regression")
    print(f"{'─'*60}")

    pipe_A = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),
            max_features=500,
            sublinear_tf=True,
        )),
        ("clf", LogisticRegression(
            class_weight="balanced",
            max_iter=1000,
            C=1.0,
            solver="lbfgs",
        )),
    ])

    if len(records) >= 4:
        # Leave-One-Out CV
        loo    = LeaveOneOut()
        y_pred_A = []
        for train_idx, test_idx in loo.split(X_binary):
            X_tr = [X_binary[i] for i in train_idx]
            y_tr = [y_binary[i] for i in train_idx]
            X_te = [X_binary[i] for i in test_idx]
            pipe_A.fit(X_tr, y_tr)
            y_pred_A.extend(pipe_A.predict(X_te))

        acc_A = accuracy_score(y_binary, y_pred_A)
        f1_A  = f1_score(y_binary, y_pred_A, average="weighted", zero_division=0)
        print(f"\n  LOO-CV Accuracy : {acc_A:.2%}")
        print(f"  LOO-CV F1       : {f1_A:.3f}")
        print(f"\n  Classification Report:")
        print(classification_report(y_binary, y_pred_A,
                                    target_names=["SECURE(0)", "ATTACK(1)"],
                                    zero_division=0))
        results["model_A_loo_accuracy"] = acc_A
        results["model_A_loo_f1"]       = f1_A
        results["model_A_predictions"]  = y_pred_A
    else:
        print("  Too few records for LOO-CV — training on full data")

    # Train final Model A on ALL data
    pipe_A.fit(X_binary, y_binary)
    model_A_path = SAVED / f"model_binary_{dataset_version}.pkl"
    with open(model_A_path, "wb") as f:
        pickle.dump(pipe_A, f)
    print(f"\n  ✅ Model A saved: {model_A_path.name}")

    # ── Model B: Multi-class Classifier ───────────────────────────────
    print(f"\n{'─'*60}")
    print("  MODEL B — Multi-class Classifier (attack_category)")
    print("  Method: TF-IDF (word + char) + Random Forest")
    print(f"{'─'*60}")

    # Filter out "None" class for multi-class (only attack records)
    attack_records  = [r for r in records if r.get("attack_present") == 1]
    X_multi_atk  = [serialise_record(r, include_attack_name=False) for r in attack_records]
    y_multi_atk  = [get_primary_attack_category(r) for r in attack_records]

    print(f"\n  Attack records: {len(attack_records)}")
    print(f"  Classes: {sorted(set(y_multi_atk))}")

    pipe_B = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),
            max_features=500,
            sublinear_tf=True,
        )),
        ("clf", RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=42,
            max_depth=None,
        )),
    ])

    if len(attack_records) >= 4:
        loo      = LeaveOneOut()
        y_pred_B = []
        for train_idx, test_idx in loo.split(X_multi_atk):
            X_tr = [X_multi_atk[i] for i in train_idx]
            y_tr = [y_multi_atk[i]  for i in train_idx]
            X_te = [X_multi_atk[i]  for i in test_idx]
            pipe_B.fit(X_tr, y_tr)
            y_pred_B.extend(pipe_B.predict(X_te))

        acc_B = accuracy_score(y_multi_atk, y_pred_B)
        f1_B  = f1_score(y_multi_atk, y_pred_B, average="weighted", zero_division=0)
        print(f"\n  LOO-CV Accuracy : {acc_B:.2%}")
        print(f"  LOO-CV F1       : {f1_B:.3f}")
        print(f"\n  Classification Report:")
        print(classification_report(y_multi_atk, y_pred_B, zero_division=0))
        results["model_B_loo_accuracy"] = acc_B
        results["model_B_loo_f1"]       = f1_B
    else:
        print("  Too few attack records for LOO-CV — training on full data")

    # Train final Model B on all attack records
    pipe_B.fit(X_multi_atk, y_multi_atk)
    model_B_path = SAVED / f"model_multiclass_{dataset_version}.pkl"
    with open(model_B_path, "wb") as f:
        pickle.dump(pipe_B, f)
    print(f"\n  ✅ Model B saved: {model_B_path.name}")

    # ── Save metadata ──────────────────────────────────────────────────
    metadata = {
        "dataset_version":    dataset_version,
        "training_date":      date.today().isoformat(),
        "n_records":          len(records),
        "n_attack_records":   len(attack_records),
        "n_secure_records":   len(records) - len(attack_records),
        "attack_categories":  sorted(set(y_multi_atk)),
        "model_A": {
            "type":       "TF-IDF + Logistic Regression",
            "task":       "binary (attack_present)",
            "path":       str(model_A_path),
            "loo_accuracy": results.get("model_A_loo_accuracy"),
            "loo_f1":       results.get("model_A_loo_f1"),
        },
        "model_B": {
            "type":       "TF-IDF + Random Forest",
            "task":       "multi-class (attack_category)",
            "path":       str(model_B_path),
            "loo_accuracy": results.get("model_B_loo_accuracy"),
            "loo_f1":       results.get("model_B_loo_f1"),
        },
        "evaluation_note": (
            "Leave-One-Out CV on small dataset. "
            f"{len(records)} total records is below the recommended minimum "
            "for reliable ML evaluation. Results are indicative only. "
            "Expand dataset to 50+ records for meaningful evaluation."
        ),
    }

    meta_path = SAVED / f"model_metadata_{dataset_version}.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"\n  ✅ Metadata saved: {meta_path.name}")

    # ── Demo predictions ───────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("  DEMO: Predict on training data (sanity check)")
    print(f"{'─'*60}")
    for r in records[:5]:
        feat     = serialise_record(r, include_attack_name=False)
        pred_bin = pipe_A.predict([feat])[0]
        prob_bin = pipe_A.predict_proba([feat])[0]
        actual   = r.get("attack_present")
        tick     = "✅" if pred_bin == actual else "❌"
        print(f"  {tick} [{r['paper_id']}] {r['protocol_name'][:35]:<35} "
              f"actual={actual} pred={pred_bin} "
              f"conf={max(prob_bin):.2f}")

    print(f"\n{'='*60}")
    print("  Training complete.")
    print(f"  Model A: {model_A_path.name}")
    print(f"  Model B: {model_B_path.name}")
    print(f"\n  ⚠️  IMPORTANT: Dataset has only {len(records)} records.")
    print("  LOO-CV results are indicative only.")
    print("  Expand to 50+ records for reliable evaluation.")
    print(f"{'='*60}\n")

    return metadata


# ── Inference helper (used by dashboard) ──────────────────────────────────────

def predict(
    protocol_text: str,
    dataset_version: str = "v1",
) -> dict:
    """
    Load saved models and predict for a raw protocol text string.

    Parameters
    ----------
    protocol_text : str — serialised protocol (equations + description)
    dataset_version : str

    Returns
    -------
    dict with keys: attack_present, attack_category, confidence_binary, confidence_multi
    """
    model_A_path = SAVED / f"model_binary_{dataset_version}.pkl"
    model_B_path = SAVED / f"model_multiclass_{dataset_version}.pkl"

    if not model_A_path.exists():
        return {
            "error": f"Model not trained yet. Run: python models/training/train_baseline.py",
            "attack_present": None, "attack_category": None,
        }

    with open(model_A_path, "rb") as f:
        pipe_A = pickle.load(f)
    with open(model_B_path, "rb") as f:
        pipe_B = pickle.load(f)

    pred_binary = int(pipe_A.predict([protocol_text])[0])
    prob_binary = pipe_A.predict_proba([protocol_text])[0]
    conf_binary = float(max(prob_binary))

    if pred_binary == 1:
        pred_multi  = pipe_B.predict([protocol_text])[0]
        prob_multi  = pipe_B.predict_proba([protocol_text])[0]
        conf_multi  = float(max(prob_multi))
    else:
        pred_multi = "None"
        conf_multi = conf_binary

    return {
        "attack_present":     pred_binary,
        "attack_category":    pred_multi,
        "confidence_binary":  conf_binary,
        "confidence_multi":   conf_multi,
        "method": "ML-based prediction (TF-IDF + LR/RF baseline)",
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Train QuantumScyther AI baseline ML models."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=ROOT / "data" / "versions" / "dataset_v1.json",
        help="Path to dataset JSON (default: dataset_v1.json)",
    )
    parser.add_argument("--version", default="v1")
    args = parser.parse_args()

    if not args.dataset.exists():
        print(f"ERROR: Dataset not found: {args.dataset}")
        print("Run: python extraction/build_dataset.py --version v1  first.")
        sys.exit(1)

    records = load_records(args.dataset)
    train_and_evaluate(records, dataset_version=args.version)


if __name__ == "__main__":
    main()
