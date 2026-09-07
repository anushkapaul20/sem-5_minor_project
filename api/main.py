"""
api/main.py
===========
QuantumScyther AI — FastAPI Backend

Endpoints
---------
GET  /health            — service health check
POST /verify            — verify a protocol, returns full analysis
POST /pqc               — check primitives for quantum vulnerability
GET  /dataset           — return dataset_v0 records for the explorer
GET  /dataset/{paper_id} — return a single record

Run with:
    uvicorn api.main:app --reload --port 8000
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.explorer import Explorer, VerificationResult
from engine.protocols.nspk    import make_nspk, make_nsl
from engine.protocols.nssk    import make_nssk
from engine.protocols.iso9798 import make_iso9798
from engine.protocols.sts     import make_sts
from engine.protocols.mqv     import make_mqv
from engine.pqc.pqc_checker   import PQCChecker
from extraction.equation_extractor import EquationExtractor
from extraction.attack_extractor   import AttackExtractor

# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="QuantumScyther AI",
    description="AI-Powered Cryptographic Protocol Verification with Post-Quantum Awareness",
    version="0.3",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pre-built protocol registry
PROTOCOL_REGISTRY = {
    "NSPK":    make_nspk,
    "NSL":     make_nsl,
    "NSSK":    make_nssk,
    "ISO9798": make_iso9798,
    "STS":     make_sts,
    "MQV":     make_mqv,
}

pqc_checker     = PQCChecker()
eq_extractor    = EquationExtractor()
atk_extractor   = AttackExtractor()


# ── Request / Response models ──────────────────────────────────────────────────

class ProtocolInput(BaseModel):
    protocol_name: str = "Custom"
    equations:     str          # raw text e.g. "A -> B : {Na,A}Kb\nB -> A : {Na,Nb}Ka"
    description:   str = ""     # optional attack description for keyword detection


class PQCInput(BaseModel):
    primitives: List[str]       # list from controlled vocabulary


class VerifyResponse(BaseModel):
    protocol_name:   str
    attack_found:    bool
    attack_type:     str
    property_violated: str
    trace:           List[str]
    explanation:     str
    states_visited:  int
    time_seconds:    float
    primitives:      List[str]
    pqc_report:      str
    keyword_detection: Dict[str, Any]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _load_dataset() -> List[Dict]:
    ds_path = ROOT / "data" / "versions" / "dataset_v0.json"
    if not ds_path.exists():
        return []
    with open(ds_path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("records", [])


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "0.3",
        "protocols_available": list(PROTOCOL_REGISTRY.keys()),
        "dataset_records": len(_load_dataset()),
    }


@app.post("/verify", response_model=VerifyResponse)
def verify(body: ProtocolInput):
    """
    Verify a protocol.

    If protocol_name matches a built-in (NSPK/NSL/NSSK/ISO9798/STS/MQV),
    runs the full symbolic engine.
    Otherwise runs keyword-based extraction on the equations text.
    """
    name = body.protocol_name.strip().upper()

    # ── Full engine path for known protocols ──────────────────────────────
    if name in PROTOCOL_REGISTRY:
        protocol  = PROTOCOL_REGISTRY[name]()
        explorer  = Explorer(max_sessions=2, timeout_seconds=25)
        result: VerificationResult = explorer.verify(protocol)

        primitives = [repr(t) for c in protocol.secrecy_claims
                      for t in [c.term]][:5]
        # Get actual primitive names from the protocol definition
        prim_names = _get_prim_names(name)

        pqc_results = pqc_checker.check(prim_names)
        pqc_report  = pqc_checker.report(pqc_results)

        keyword = atk_extractor.extract_attack_info(body.equations + "\n" + body.description)

        return VerifyResponse(
            protocol_name=name,
            attack_found=result.attack_found,
            attack_type=result.attack_type,
            property_violated=result.property,
            trace=result.trace,
            explanation=result.explanation,
            states_visited=result.states_visited,
            time_seconds=result.time_seconds,
            primitives=prim_names,
            pqc_report=pqc_report,
            keyword_detection=keyword,
        )

    # ── Keyword-only path for custom protocols ────────────────────────────
    messages   = eq_extractor.extract(body.equations)
    prim_names = eq_extractor.identify_primitives(body.equations)
    keyword    = atk_extractor.extract_attack_info(body.equations + "\n" + body.description)

    pqc_results = pqc_checker.check(prim_names)
    pqc_report  = pqc_checker.report(pqc_results)

    return VerifyResponse(
        protocol_name=body.protocol_name,
        attack_found=bool(keyword.get("attack_present")),
        attack_type=", ".join(keyword.get("attack_category", ["None"])),
        property_violated=", ".join(keyword.get("security_property_targeted", [])),
        trace=[f"Step {m.step}: {m.sender} → {m.receiver} : {m.message}"
               for m in messages],
        explanation=(
            f"Keyword-based detection only (custom protocol). "
            f"Confidence: {keyword.get('confidence', 'NONE')}. "
            f"For formal verification, use a built-in protocol name."
        ),
        states_visited=0,
        time_seconds=0.0,
        primitives=prim_names,
        pqc_report=pqc_report,
        keyword_detection=keyword,
    )


@app.post("/pqc")
def check_pqc(body: PQCInput):
    results = pqc_checker.check(body.primitives)
    return {
        "results": [
            {
                "primitive": r.primitive,
                "risk":      r.risk,
                "threat":    r.threat,
                "replacement": r.replacement,
                "fips":      r.fips,
                "is_vulnerable": r.is_vulnerable,
            }
            for r in results
        ],
        "report": pqc_checker.report(results),
        "has_vulnerabilities": pqc_checker.has_vulnerabilities(body.primitives),
    }


@app.get("/dataset")
def get_dataset():
    records = _load_dataset()
    # Return a lightweight summary
    return {
        "total": len(records),
        "records": [
            {
                "paper_id":      r.get("paper_id"),
                "paper_title":   r.get("paper_title"),
                "authors":       r.get("authors"),
                "year":          r.get("publication_year"),
                "protocol_name": r.get("protocol_name"),
                "attack_present": r.get("attack_present"),
                "attack_category": r.get("attack_category"),
                "source_link":   r.get("source_link"),
                "primitives":    r.get("cryptographic_primitives", []),
                "message_count": r.get("message_step_count"),
                "extraction_status": r.get("extraction_status"),
            }
            for r in records
        ],
    }


@app.get("/dataset/{paper_id}")
def get_paper(paper_id: str):
    records = _load_dataset()
    for r in records:
        if r.get("paper_id") == paper_id:
            return r
    raise HTTPException(status_code=404, detail=f"Paper '{paper_id}' not found")


@app.get("/benchmark")
def run_benchmark():
    """Run quick benchmark and return results."""
    cases = [
        ("NSPK",    True),
        ("NSL",     False),
        ("NSSK",    True),
        ("ISO9798", True),
        ("STS",     True),
        ("MQV",     True),
    ]
    results = []
    explorer = Explorer(max_sessions=2, timeout_seconds=20)
    for name, expected in cases:
        protocol = PROTOCOL_REGISTRY[name]()
        r = explorer.verify(protocol)
        results.append({
            "protocol":       name,
            "expected":       "ATTACK" if expected else "SECURE",
            "got":            "ATTACK" if r.attack_found else "SECURE",
            "attack_type":    r.attack_type,
            "correct":        r.attack_found == expected,
            "states_visited": r.states_visited,
            "time_seconds":   round(r.time_seconds, 3),
        })

    correct  = sum(1 for r in results if r["correct"])
    accuracy = correct / len(results)
    return {
        "accuracy":       accuracy,
        "correct":        correct,
        "total":          len(results),
        "target":         0.85,
        "target_met":     accuracy >= 0.85,
        "results":        results,
    }


def _get_prim_names(protocol_name: str) -> List[str]:
    mapping = {
        "NSPK":    ["Public_Key_Encryption", "Nonce"],
        "NSL":     ["Public_Key_Encryption", "Nonce"],
        "NSSK":    ["Symmetric_Encryption", "Nonce", "Session_Key", "Shared_Secret"],
        "ISO9798": ["Symmetric_Encryption", "Nonce", "Shared_Secret", "Challenge_Response"],
        "STS":     ["Diffie-Hellman", "Digital_Signature", "Certificate", "Symmetric_Encryption", "Session_Key"],
        "MQV":     ["Diffie-Hellman", "Hash", "Session_Key", "Shared_Secret"],
    }
    return mapping.get(protocol_name.upper(), [])
