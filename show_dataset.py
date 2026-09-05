"""show_dataset.py — Print a clean view of dataset_v0."""
import json, os

path = os.path.join(os.path.dirname(__file__), "data", "versions", "dataset_v0.json")
with open(path, encoding="utf-8") as f:
    data = json.load(f)

meta    = data["metadata"]
records = data["records"]

W = 68
print("=" * W)
print("  QuantumScyther AI  —  Dataset v0")
print("=" * W)
print(f"  Total records      : {meta['record_count']}")
print(f"  Attack present (1) : {meta['attack_present_count']}")
print(f"  Secure     (0)     : {meta['attack_absent_count']}")
print(f"  Created            : {meta['created_date']}")
print(f"  Schema version     : {meta['schema_version']}")
print()

# ── Per-record table ──────────────────────────────────────────────────────────
print(f"  {'ID':<12} {'Protocol':<34} {'Atk':^4}  {'Attack Category'}")
print(f"  {'-'*12} {'-'*34} {'-'*4}  {'-'*30}")
for r in records:
    cats = ", ".join(r["attack_category"])
    prot = r["protocol_name"][:33]
    pid  = r["paper_id"]
    atk  = str(r["attack_present"])
    print(f"  {pid:<12} {prot:<34} {atk:^4}  {cats}")

# ── Attack category chart ─────────────────────────────────────────────────────
print()
print("  Attack category breakdown:")
cats: dict = {}
for r in records:
    for c in r["attack_category"]:
        cats[c] = cats.get(c, 0) + 1
for cat, count in sorted(cats.items()):
    bar  = "█" * count
    print(f"    {cat:<35} {bar}  ({count})")

# ── Source papers ─────────────────────────────────────────────────────────────
print()
print("  Source papers:")
for r in records:
    print(f"    [{r['paper_id']}]  {r['paper_title'][:55]}")
    print(f"             {r['authors']} ({r['publication_year']})")
    if r.get("source_link","").startswith("http"):
        print(f"             {r['source_link']}")

# ── Primitive coverage ────────────────────────────────────────────────────────
print()
print("  Cryptographic primitives across all records:")
prims: dict = {}
for r in records:
    for p in r.get("cryptographic_primitives", []):
        prims[p] = prims.get(p, 0) + 1
for p, count in sorted(prims.items(), key=lambda x: -x[1]):
    bar = "█" * count
    print(f"    {p:<30} {bar}  ({count})")

# ── Verification status ───────────────────────────────────────────────────────
print()
print("  Extraction status:")
for status in ["HUMAN_VERIFIED", "AUTO_EXTRACTED", "REQUIRES_REVIEW"]:
    n = sum(1 for r in records if r["extraction_status"] == status)
    if n:
        print(f"    {status:<25} {n}")

print()
print("  Files on disk:")
import os
for fname in ["dataset_v0.csv", "dataset_v0.json", "dataset_review_v0.xlsx"]:
    fpath = os.path.join("data", "versions", fname)
    size  = os.path.getsize(fpath) // 1024
    print(f"    {fname:<35} {size} KB")
print()
print("=" * W)
