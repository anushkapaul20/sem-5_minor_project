"""
tests/test_dataset_v0.py
=========================
Integration tests — verify that the generated dataset_v0 files
exist, are non-empty, and contain valid data.

These tests run AFTER build_dataset.py has been executed.
They do NOT re-run the builder; they validate what was already built.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

VERSIONS_DIR = ROOT / "data" / "versions"
RAW_DIR = ROOT / "data" / "raw"

from extraction.annotation_schema import CSV_COLUMNS, ProtocolRecord

# ── File existence ────────────────────────────────────────────────────────────

def test_dataset_json_exists():
    assert (VERSIONS_DIR / "dataset_v0.json").exists(), \
        "dataset_v0.json not found — run: python extraction/build_dataset.py"


def test_dataset_csv_exists():
    assert (VERSIONS_DIR / "dataset_v0.csv").exists(), \
        "dataset_v0.csv not found — run: python extraction/build_dataset.py"


def test_dataset_xlsx_exists():
    assert (VERSIONS_DIR / "dataset_review_v0.xlsx").exists(), \
        "dataset_review_v0.xlsx not found — run: python extraction/build_dataset.py"


# ── Raw files ─────────────────────────────────────────────────────────────────

def test_all_raw_files_exist():
    expected = [
        "paper_001_raw.json",
        "paper_001b_raw.json",
        "paper_002_raw.json",
        "paper_003_raw.json",
        "paper_004_raw.json",
        "paper_005_raw.json",
    ]
    for fname in expected:
        assert (RAW_DIR / fname).exists(), f"Missing raw file: {fname}"


# ── JSON content ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def dataset_json():
    with open(VERSIONS_DIR / "dataset_v0.json", encoding="utf-8") as fh:
        return json.load(fh)


def test_json_has_metadata(dataset_json):
    assert "metadata" in dataset_json
    assert "records" in dataset_json


def test_json_record_count(dataset_json):
    assert len(dataset_json["records"]) == 6


def test_json_metadata_counts(dataset_json):
    meta = dataset_json["metadata"]
    assert meta["record_count"] == 6
    assert meta["attack_present_count"] == 5
    assert meta["attack_absent_count"] == 1


def test_all_records_load_as_protocol_record(dataset_json):
    for raw in dataset_json["records"]:
        r = ProtocolRecord.from_dict(raw)
        assert r.paper_id != ""


def test_all_records_pass_validation(dataset_json):
    for raw in dataset_json["records"]:
        r = ProtocolRecord.from_dict(raw)
        errors = r.validate()
        assert errors == [], \
            f"Record {r.paper_id} failed validation: {errors}"


# ── Required paper IDs present ────────────────────────────────────────────────

def test_all_paper_ids_present(dataset_json):
    ids = {r["paper_id"] for r in dataset_json["records"]}
    expected = {"paper_001", "paper_001b", "paper_002", "paper_003", "paper_004", "paper_005"}
    assert expected == ids


# ── Attack category coverage ──────────────────────────────────────────────────

def test_mitm_present(dataset_json):
    cats = [cat for r in dataset_json["records"] for cat in r["attack_category"]]
    assert "MITM" in cats


def test_replay_present(dataset_json):
    cats = [cat for r in dataset_json["records"] for cat in r["attack_category"]]
    assert "Replay" in cats


def test_reflection_present(dataset_json):
    cats = [cat for r in dataset_json["records"] for cat in r["attack_category"]]
    assert "Reflection" in cats


def test_uks_present(dataset_json):
    cats = [cat for r in dataset_json["records"] for cat in r["attack_category"]]
    assert "UKS" in cats


def test_kci_present(dataset_json):
    cats = [cat for r in dataset_json["records"] for cat in r["attack_category"]]
    assert "KCI" in cats


def test_secure_record_present(dataset_json):
    secure = [r for r in dataset_json["records"] if r["attack_present"] == 0]
    assert len(secure) >= 1


# ── Dataset balance ───────────────────────────────────────────────────────────

def test_dataset_not_all_attack(dataset_json):
    """Dataset must have at least one secure (attack_present=0) record."""
    no_attack = sum(1 for r in dataset_json["records"] if r["attack_present"] == 0)
    assert no_attack >= 1


# ── CSV content ───────────────────────────────────────────────────────────────

def test_csv_has_correct_columns():
    import pandas as pd
    df = pd.read_csv(VERSIONS_DIR / "dataset_v0.csv")
    for col in CSV_COLUMNS:
        assert col in df.columns, f"CSV missing column: {col}"


def test_csv_row_count():
    import pandas as pd
    df = pd.read_csv(VERSIONS_DIR / "dataset_v0.csv")
    assert len(df) == 6


def test_csv_paper_id_unique():
    import pandas as pd
    df = pd.read_csv(VERSIONS_DIR / "dataset_v0.csv")
    assert df["paper_id"].nunique() == 6


# ── Source links non-empty for confirmed papers ───────────────────────────────

def test_source_links_present(dataset_json):
    """Papers 001, 002, 004, 005 have confirmed DOI links."""
    link_map = {r["paper_id"]: r["source_link"] for r in dataset_json["records"]}
    for pid in ("paper_001", "paper_002", "paper_004", "paper_005"):
        assert link_map[pid].startswith("https://"), \
            f"{pid} missing valid source link"


# ── Original equations non-empty ──────────────────────────────────────────────

def test_original_equations_nonempty(dataset_json):
    for r in dataset_json["records"]:
        assert r["original_equations"] not in ("", None, "REQUIRES_MANUAL_VERIFICATION"), \
            f"paper_id={r['paper_id']} has empty original_equations"


# ── Message step count correct ────────────────────────────────────────────────

def test_nspk_has_3_steps(dataset_json):
    r = next(x for x in dataset_json["records"] if x["paper_id"] == "paper_001")
    assert r["message_step_count"] == 3


def test_nssk_has_5_steps(dataset_json):
    r = next(x for x in dataset_json["records"] if x["paper_id"] == "paper_002")
    assert r["message_step_count"] == 5


def test_mqv_has_2_steps(dataset_json):
    r = next(x for x in dataset_json["records"] if x["paper_id"] == "paper_005")
    assert r["message_step_count"] == 2
