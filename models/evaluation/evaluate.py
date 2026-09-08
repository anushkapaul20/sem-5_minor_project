"""
models/evaluation/evaluate.py
==============================
Print a clean evaluation report for the trained baseline models.

Run from project root:
    python models/evaluation/evaluate.py
"""
import json, pickle, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from models.training.train_baseline import load_records, serialise_record, get_primary_attack_category

SAVED = ROOT / "models" / "saved_models"


def main():
    meta_path = SAVED / "model_metadata_v1.json"
    if not meta_path.exists():
        print("ERROR: Models not trained yet. Run: python models/training/train_baseline.py")
        sys.exit(1)

    meta = json.load(open(meta_path, encoding="utf-8"))
    records = load_records(ROOT / "data" / "versions" / "dataset_v1.json")

    pipe_A = pickle.load(open(SAVED / "model_binary_v1.pkl", "rb"))
    pipe_B = pickle.load(open(SAVED / "model_multiclass_v1.pkl", "rb"))

    W = 62
    print("=" * W)
    print("  QuantumScyther AI — ML Model Evaluation Report")
    print("=" * W)
    print(f"  Dataset version : {meta['dataset_version']}")
    print(f"  Training date   : {meta['training_date']}")
    print(f"  Total records   : {meta['n_records']}")
    print(f"  Attack records  : {meta['n_attack_records']}")
    print(f"  Secure records  : {meta['n_secure_records']}")

    print(f"\n{'─'*W}")
    print("  MODEL A — Binary Classifier (attack_present)")
    print(f"  Type: {meta['model_A']['type']}")
    acc_A = meta['model_A'].get('loo_accuracy')
    f1_A  = meta['model_A'].get('loo_f1')
    print(f"  LOO-CV Accuracy : {acc_A:.2%}" if acc_A else "  Accuracy: N/A")
    print(f"  LOO-CV F1       : {f1_A:.3f}"  if f1_A  else "  F1: N/A")

    print(f"\n{'─'*W}")
    print("  MODEL B — Multi-class Classifier (attack_category)")
    print(f"  Type: {meta['model_B']['type']}")
    acc_B = meta['model_B'].get('loo_accuracy')
    f1_B  = meta['model_B'].get('loo_f1')
    print(f"  LOO-CV Accuracy : {acc_B:.2%}" if acc_B else "  Accuracy: N/A")
    print(f"  LOO-CV F1       : {f1_B:.3f}"  if f1_B  else "  F1: N/A")
    print(f"  Classes         : {meta['attack_categories']}")

    print(f"\n{'─'*W}")
    print("  Per-record predictions (Model A + Model B)")
    print(f"{'─'*W}")
    print(f"  {'ID':<12} {'Protocol':<32} {'Act':^4} {'PredA':^5} {'Category':<20} {'Conf':>5}")
    print(f"  {'-'*12} {'-'*32} {'-'*4} {'-'*5} {'-'*20} {'-'*5}")

    correct_A = 0
    for r in records:
        feat  = serialise_record(r, include_attack_name=False)
        predA = int(pipe_A.predict([feat])[0])
        probA = pipe_A.predict_proba([feat])[0]
        confA = max(probA)
        actual = r.get("attack_present", 0)
        if actual == 1:
            predB = pipe_B.predict([feat])[0]
        else:
            predB = "None"
        tick = "✓" if predA == actual else "✗"
        correct_A += int(predA == actual)
        print(f"  [{tick}] {r['paper_id']:<10} {r['protocol_name'][:31]:<32} "
              f"{actual:^4} {predA:^5} {predB:<20} {confA:.2f}")

    print(f"\n  Model A training accuracy: {correct_A}/{len(records)} = {correct_A/len(records):.0%}")
    print(f"\n  ⚠️  {meta['evaluation_note']}")
    print("=" * W)


if __name__ == "__main__":
    main()
