"""
build_dataset.py
================
Reads all raw paper JSON records from data/raw/, validates each one against
the ProtocolRecord schema, and writes:

  data/versions/dataset_v0.json     — machine-readable, all records
  data/versions/dataset_v0.csv      — flat CSV (JSON lists serialised as strings)
  data/annotations/dataset_review_v0.xlsx — human-readable review sheet

Run from the project root:
  python extraction/build_dataset.py

Or with a custom output directory:
  python extraction/build_dataset.py --output data/versions --version v0
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path
from typing import List, Tuple

import pandas as pd

# ── Add project root to path so extraction.* imports work ────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from extraction.annotation_schema import (
    CSV_COLUMNS,
    ProtocolRecord,
    ValidationError,
)

# ── ANSI colours for terminal output ─────────────────────────────────────────
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"


# ── Helper: load one raw JSON → ProtocolRecord ────────────────────────────────

def load_raw_record(json_path: Path) -> Tuple[ProtocolRecord, List[str]]:
    """
    Load a raw JSON file and return (record, validation_errors).
    Fields in the JSON that are not in ProtocolRecord are silently ignored.
    The _meta key is always ignored.
    """
    with open(json_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    # Remove internal metadata key
    data.pop("_meta", None)

    record = ProtocolRecord.from_dict(data)
    errors = record.validate()
    return record, errors


# ── Helper: serialise list/dict fields for CSV ────────────────────────────────

def _csv_value(val) -> str:
    """
    Convert a field value to a CSV-safe string.
    Lists and dicts are serialised as compact JSON strings.
    Booleans are lowercased strings.
    """
    if val is None:
        return ""
    if isinstance(val, bool):
        return str(val).lower()
    if isinstance(val, (list, dict)):
        return json.dumps(val, ensure_ascii=False)
    return str(val)


# ── Main build function ────────────────────────────────────────────────────────

def build_dataset(
    raw_dir: Path,
    output_dir: Path,
    version: str = "v0",
    strict: bool = False,
) -> List[ProtocolRecord]:
    """
    Read all *_raw.json files from raw_dir, validate them, and write outputs.

    Parameters
    ----------
    raw_dir   : directory containing paper_XXX_raw.json files
    output_dir: directory to write dataset_v{N}.* files
    version   : version suffix, e.g. "v0"
    strict    : if True, abort on first validation error

    Returns
    -------
    List of validated ProtocolRecord objects.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    raw_files = sorted(raw_dir.glob("*_raw.json"))
    if not raw_files:
        print(f"{RED}ERROR: No *_raw.json files found in {raw_dir}{RESET}")
        sys.exit(1)

    print(f"\n{BOLD}=== Dataset Builder v{version} ==={RESET}")
    print(f"Source directory : {raw_dir}")
    print(f"Output directory : {output_dir}")
    print(f"Found {len(raw_files)} raw file(s)\n")

    records: List[ProtocolRecord] = []
    all_errors: dict[str, List[str]] = {}

    for fpath in raw_files:
        record, errors = load_raw_record(fpath)
        if errors:
            all_errors[fpath.name] = errors
            if strict:
                print(f"{RED}STRICT MODE: Aborting on first error in {fpath.name}{RESET}")
                for e in errors:
                    print(f"  - {e}")
                sys.exit(1)
            else:
                print(f"{YELLOW}⚠  {fpath.name} — {len(errors)} validation issue(s){RESET}")
                for e in errors:
                    print(f"     • {e}")
        else:
            print(f"{GREEN}✓  {fpath.name} — {record.paper_id} | {record.protocol_name[:50]}{RESET}")
        records.append(record)

    print(f"\nTotal records loaded : {len(records)}")
    print(f"Records with issues  : {len(all_errors)}")
    print(f"Clean records        : {len(records) - len(all_errors)}")

    if not records:
        print(f"{RED}No records to write. Exiting.{RESET}")
        sys.exit(1)

    # ── Write JSON ────────────────────────────────────────────────────────────
    json_path = output_dir / f"dataset_{version}.json"
    dataset_json = {
        "metadata": {
            "version": version,
            "created_date": date.today().isoformat(),
            "record_count": len(records),
            "schema_version": "0.1",
            "attack_present_count": sum(r.attack_present for r in records),
            "attack_absent_count": sum(1 for r in records if r.attack_present == 0),
        },
        "records": [r.to_dict() for r in records],
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(dataset_json, fh, indent=2, ensure_ascii=False)
    print(f"\n{GREEN}✓  JSON written  : {json_path}{RESET}")

    # ── Write CSV ─────────────────────────────────────────────────────────────
    csv_path = output_dir / f"dataset_{version}.csv"
    rows = []
    for r in records:
        d = r.to_dict()
        row = {col: _csv_value(d.get(col)) for col in CSV_COLUMNS}
        rows.append(row)
    df = pd.DataFrame(rows, columns=CSV_COLUMNS)
    df.to_csv(csv_path, index=False, encoding="utf-8-sig")
    print(f"{GREEN}✓  CSV written   : {csv_path}{RESET}")

    # ── Write XLSX review sheet ───────────────────────────────────────────────
    xlsx_path = output_dir / f"dataset_review_{version}.xlsx"
    _write_review_xlsx(records, df, xlsx_path, version)
    print(f"{GREEN}✓  XLSX written  : {xlsx_path}{RESET}")

    # ── Print summary table ───────────────────────────────────────────────────
    _print_summary(records)

    # ── Write validation report ───────────────────────────────────────────────
    if all_errors:
        report_path = output_dir / f"validation_report_{version}.txt"
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(f"Dataset Validation Report — {version}\n")
            fh.write(f"Generated: {date.today().isoformat()}\n\n")
            for fname, errs in all_errors.items():
                fh.write(f"File: {fname}\n")
                for e in errs:
                    fh.write(f"  - {e}\n")
                fh.write("\n")
        print(f"{YELLOW}⚠  Validation report: {report_path}{RESET}")

    return records


# ── XLSX writer ────────────────────────────────────────────────────────────────

def _write_review_xlsx(
    records: List[ProtocolRecord],
    df: pd.DataFrame,
    xlsx_path: Path,
    version: str,
) -> None:
    """
    Write a human-friendly Excel workbook with:
      Sheet 1: Dataset — all records, colour-coded by extraction_status
      Sheet 2: Validation Checklist — one row per record, checklist columns
      Sheet 3: Summary — statistics
    """
    try:
        import openpyxl
        from openpyxl.styles import (
            Alignment, Font, PatternFill, Border, Side
        )
        from openpyxl.utils.dataframe import dataframe_to_rows
    except ImportError:
        print(f"{YELLOW}openpyxl not installed — skipping XLSX output{RESET}")
        return

    wb = openpyxl.Workbook()

    # ── Sheet 1: Full Dataset ─────────────────────────────────────────────────
    ws1 = wb.active
    ws1.title = "Dataset"

    # Header row
    header_fill = PatternFill("solid", fgColor="1F4E79")
    header_font = Font(color="FFFFFF", bold=True, size=10)
    thin = Side(style="thin", color="AAAAAA")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)

    for col_idx, col_name in enumerate(CSV_COLUMNS, start=1):
        cell = ws1.cell(row=1, column=col_idx, value=col_name)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center", wrap_text=True)
        cell.border = border

    # Status colour map
    STATUS_FILLS = {
        "HUMAN_VERIFIED": PatternFill("solid", fgColor="C6EFCE"),     # green
        "AUTO_EXTRACTED": PatternFill("solid", fgColor="FFEB9C"),     # yellow
        "REQUIRES_REVIEW": PatternFill("solid", fgColor="FFC7CE"),    # red/pink
    }

    for row_idx, record in enumerate(records, start=2):
        d = record.to_dict()
        status = record.extraction_status
        row_fill = STATUS_FILLS.get(status, PatternFill())

        for col_idx, col_name in enumerate(CSV_COLUMNS, start=1):
            val = _csv_value(d.get(col_name))
            cell = ws1.cell(row=row_idx, column=col_idx, value=val)
            cell.fill = row_fill
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            cell.border = border
            cell.font = Font(size=9)

    # Freeze panes and auto-filter
    ws1.freeze_panes = "A2"
    ws1.auto_filter.ref = f"A1:{openpyxl.utils.get_column_letter(len(CSV_COLUMNS))}1"

    # Column widths
    WIDE_COLS = {
        "paper_title": 40, "original_equations": 50,
        "attack_trace": 60, "security_violation": 50,
        "notes": 40, "authors": 25,
    }
    for col_idx, col_name in enumerate(CSV_COLUMNS, start=1):
        letter = openpyxl.utils.get_column_letter(col_idx)
        ws1.column_dimensions[letter].width = WIDE_COLS.get(col_name, 18)

    # ── Sheet 2: Validation Checklist ────────────────────────────────────────
    ws2 = wb.create_sheet("Validation Checklist")
    checklist_headers = [
        "paper_id", "protocol_name",
        "✓ Paper exists",
        "✓ Source link works",
        "✓ Protocol name verified",
        "✓ Equations verified",
        "✓ Message sequence verified",
        "✓ Participants verified",
        "✓ Primitives verified",
        "✓ Attacker model verified",
        "✓ Attack verified",
        "✓ Attack trace verified",
        "✓ Security property verified",
        "✓ Page number recorded",
        "✓ Dataset label verified",
        "Reviewer",
        "Date verified",
        "Comments",
    ]

    for col_idx, h in enumerate(checklist_headers, start=1):
        cell = ws2.cell(row=1, column=col_idx, value=h)
        cell.fill = PatternFill("solid", fgColor="375623")
        cell.font = Font(color="FFFFFF", bold=True, size=10)
        cell.alignment = Alignment(horizontal="center", wrap_text=True)

    for row_idx, record in enumerate(records, start=2):
        ws2.cell(row=row_idx, column=1, value=record.paper_id)
        ws2.cell(row=row_idx, column=2, value=record.protocol_name)
        # Pre-fill checklist based on extraction_status
        is_verified = record.extraction_status == "HUMAN_VERIFIED"
        check = "YES" if is_verified else "PENDING"
        for col_idx in range(3, 16):
            cell = ws2.cell(row=row_idx, column=col_idx, value=check)
            cell.alignment = Alignment(horizontal="center")
            if is_verified:
                cell.fill = PatternFill("solid", fgColor="C6EFCE")
            else:
                cell.fill = PatternFill("solid", fgColor="FFEB9C")
        ws2.cell(row=row_idx, column=16, value=record.verified_by or "")
        ws2.cell(row=row_idx, column=17, value=record.last_verified_date or "")
        ws2.cell(row=row_idx, column=18, value=record.notes or "")

    ws2.freeze_panes = "A2"
    for col_idx in range(1, len(checklist_headers) + 1):
        letter = openpyxl.utils.get_column_letter(col_idx)
        ws2.column_dimensions[letter].width = 22 if col_idx > 2 else 15

    # ── Sheet 3: Summary ──────────────────────────────────────────────────────
    ws3 = wb.create_sheet("Summary")
    ws3.cell(row=1, column=1, value=f"Dataset {version} — Summary").font = Font(bold=True, size=14)
    ws3.cell(row=2, column=1, value=f"Generated: {date.today().isoformat()}")

    summary_data = [
        ("Total records", len(records)),
        ("attack_present = 1 (vulnerable)", sum(r.attack_present for r in records)),
        ("attack_present = 0 (secure)", sum(1 for r in records if r.attack_present == 0)),
        ("HUMAN_VERIFIED", sum(1 for r in records if r.extraction_status == "HUMAN_VERIFIED")),
        ("AUTO_EXTRACTED", sum(1 for r in records if r.extraction_status == "AUTO_EXTRACTED")),
        ("REQUIRES_REVIEW", sum(1 for r in records if r.extraction_status == "REQUIRES_REVIEW")),
        ("", ""),
        ("Attack category breakdown", ""),
    ]

    # Count attack categories
    cat_counts: dict[str, int] = {}
    for r in records:
        for cat in r.attack_category:
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
    for cat, count in sorted(cat_counts.items()):
        summary_data.append((f"  {cat}", count))

    for row_idx, (label, value) in enumerate(summary_data, start=4):
        ws3.cell(row=row_idx, column=1, value=label)
        ws3.cell(row=row_idx, column=2, value=value)

    ws3.column_dimensions["A"].width = 40
    ws3.column_dimensions["B"].width = 15

    wb.save(xlsx_path)


# ── Summary table ─────────────────────────────────────────────────────────────

def _print_summary(records: List[ProtocolRecord]) -> None:
    attack_counts: dict[str, int] = {}
    for r in records:
        for cat in r.attack_category:
            attack_counts[cat] = attack_counts.get(cat, 0) + 1

    print(f"\n{BOLD}=== Dataset Summary ==={RESET}")
    print(f"  Total records      : {len(records)}")
    print(f"  attack_present = 1 : {sum(r.attack_present for r in records)}")
    print(f"  attack_present = 0 : {sum(1 for r in records if r.attack_present == 0)}")
    print(f"\n  Attack categories:")
    for cat, count in sorted(attack_counts.items()):
        print(f"    {cat:<35} {count}")
    print(f"\n  Extraction status:")
    for status in ("HUMAN_VERIFIED", "AUTO_EXTRACTED", "REQUIRES_REVIEW"):
        n = sum(1 for r in records if r.extraction_status == status)
        print(f"    {status:<25} {n}")


# ── CLI entry point ────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build dataset_v{N}.csv / .json / .xlsx from raw paper JSON files."
    )
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=ROOT / "data" / "raw",
        help="Directory containing *_raw.json files (default: data/raw/)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "data" / "versions",
        help="Output directory (default: data/versions/)",
    )
    parser.add_argument(
        "--version",
        default="v0",
        help="Dataset version suffix (default: v0)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Abort on first validation error instead of continuing",
    )
    args = parser.parse_args()

    build_dataset(
        raw_dir=args.raw_dir,
        output_dir=args.output,
        version=args.version,
        strict=args.strict,
    )


if __name__ == "__main__":
    main()
