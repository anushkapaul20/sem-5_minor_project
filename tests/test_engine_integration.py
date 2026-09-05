"""
tests/test_engine_integration.py
=================================
End-to-end integration tests for the QuantumScyther AI engine.

Runs the BFS Explorer against all 6 benchmark protocols and verifies
the engine produces the correct verdict for each.

Expected results (from the dataset / source papers):
  paper_001  NSPK      → ATTACK FOUND  (MITM / Auth violation)
  paper_001b NSL       → SECURE
  paper_002  NSSK      → ATTACK FOUND  (Replay / Auth violation)
  paper_003  ISO9798   → ATTACK FOUND  (Reflection / Auth violation)
  paper_004  STS       → ATTACK FOUND  (UKS / Auth violation)
  paper_005  MQV       → ATTACK FOUND  (Secrecy violation / KCI)

These tests MUST run within the time budget (30 s per protocol).
"""
import sys
import time
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.explorer import Explorer, VerificationResult
from engine.protocols.nspk    import make_nspk, make_nsl
from engine.protocols.nssk    import make_nssk
from engine.protocols.iso9798 import make_iso9798
from engine.protocols.sts     import make_sts
from engine.protocols.mqv     import make_mqv


TIMEOUT = 30   # seconds per verification


def _run(protocol_fn, max_sessions=2) -> VerificationResult:
    """Helper: build protocol, run explorer, return result."""
    return Explorer(
        max_sessions=max_sessions,
        timeout_seconds=TIMEOUT,
        verbose=False,
    ).verify(protocol_fn())


# ── Smoke: all protocols build without error ───────────────────────────────────

def test_nspk_builds():
    p = make_nspk()
    assert p.name == "NSPK"
    assert len(p.roles) == 2

def test_nsl_builds():
    p = make_nsl()
    assert p.name == "NSL"

def test_nssk_builds():
    p = make_nssk()
    assert p.name == "NSSK"
    assert len(p.roles) == 3

def test_iso9798_builds():
    p = make_iso9798()
    assert p.name == "ISO9798"

def test_sts_builds():
    p = make_sts()
    assert p.name == "STS"

def test_mqv_builds():
    p = make_mqv()
    assert p.name == "MQV"


# ── Explorer smoke (runs without crash) ────────────────────────────────────────

def test_explorer_runs_nspk():
    r = _run(make_nspk)
    assert isinstance(r, VerificationResult)
    assert r.states_visited > 0
    assert r.time_seconds < TIMEOUT

def test_explorer_runs_nsl():
    r = _run(make_nsl)
    assert isinstance(r, VerificationResult)

def test_explorer_runs_nssk():
    r = _run(make_nssk)
    assert isinstance(r, VerificationResult)

def test_explorer_runs_iso9798():
    r = _run(make_iso9798)
    assert isinstance(r, VerificationResult)

def test_explorer_runs_sts():
    r = _run(make_sts)
    assert isinstance(r, VerificationResult)

def test_explorer_runs_mqv():
    r = _run(make_mqv)
    assert isinstance(r, VerificationResult)


# ── Verdict tests ─────────────────────────────────────────────────────────────

def test_nspk_attack_found():
    """paper_001: NSPK must report an attack."""
    r = _run(make_nspk)
    print(f"\n  NSPK: attack_found={r.attack_found}, "
          f"type={r.attack_type}, states={r.states_visited}")
    assert r.attack_found, (
        f"Expected attack on NSPK but got SECURE. "
        f"States visited: {r.states_visited}. "
        f"This is a known MITM-vulnerable protocol (Lowe 1996)."
    )


def test_nsl_secure():
    """paper_001b: NSL (Lowe fix) must be SECURE within 2 sessions."""
    r = _run(make_nsl)
    print(f"\n  NSL: attack_found={r.attack_found}, "
          f"states={r.states_visited}")
    assert not r.attack_found, (
        f"NSL should be secure but engine found: {r.attack_type}. "
        f"Trace: {r.trace[:3]}"
    )


def test_nssk_attack_found():
    """paper_002: NSSK must report an attack (replay)."""
    r = _run(make_nssk)
    print(f"\n  NSSK: attack_found={r.attack_found}, "
          f"type={r.attack_type}, states={r.states_visited}")
    assert r.attack_found, (
        f"Expected attack on NSSK but got SECURE. "
        f"This protocol is vulnerable to ticket replay (Denning-Sacco 1981)."
    )


def test_iso9798_attack_found():
    """paper_003: ISO 9798-2 style must report an attack (reflection)."""
    r = _run(make_iso9798)
    print(f"\n  ISO9798: attack_found={r.attack_found}, "
          f"type={r.attack_type}, states={r.states_visited}")
    assert r.attack_found, (
        f"Expected attack on ISO9798 but got SECURE. "
        f"This protocol is vulnerable to reflection (Syverson 1994)."
    )


def test_sts_attack_found():
    """paper_004: STS must report an attack (UKS)."""
    r = _run(make_sts)
    print(f"\n  STS: attack_found={r.attack_found}, "
          f"type={r.attack_type}, states={r.states_visited}")
    assert r.attack_found, (
        f"Expected attack on STS but got SECURE. "
        f"This protocol has a UKS attack (Blake-Wilson & Menezes 1999)."
    )


def test_mqv_attack_found():
    """paper_005: MQV must report an attack (KCI / secrecy violation)."""
    r = _run(make_mqv)
    print(f"\n  MQV: attack_found={r.attack_found}, "
          f"type={r.attack_type}, states={r.states_visited}")
    assert r.attack_found, (
        f"Expected attack on MQV but got SECURE. "
        f"This protocol has a KCI attack (Blake-Wilson et al. 1997)."
    )


# ── Attack type checks ────────────────────────────────────────────────────────

def test_nspk_attack_type_in_expected():
    r = _run(make_nspk)
    if r.attack_found:
        expected = {
            "MITM", "Authentication_Violation", "Secrecy_Violation", "Replay"
        }
        assert r.attack_type in expected, (
            f"Unexpected attack type for NSPK: {r.attack_type}"
        )


def test_nssk_attack_type_in_expected():
    r = _run(make_nssk)
    if r.attack_found:
        expected = {"Replay", "Authentication_Violation", "Secrecy_Violation"}
        assert r.attack_type in expected


def test_iso9798_attack_type_in_expected():
    r = _run(make_iso9798)
    if r.attack_found:
        expected = {"Reflection", "Authentication_Violation", "Replay"}
        assert r.attack_type in expected


# ── VerificationResult.report() ────────────────────────────────────────────────

def test_report_contains_result_line():
    r = _run(make_nspk)
    report = r.report()
    assert "ATTACK" in report or "SECURE" in report

def test_report_contains_states_visited():
    r = _run(make_nsl)
    assert "States visited" in r.report()


# ── Timing ────────────────────────────────────────────────────────────────────

def test_all_protocols_within_timeout():
    """All 6 protocols must complete within the time budget."""
    protocols = [make_nspk, make_nsl, make_nssk, make_iso9798, make_sts, make_mqv]
    for fn in protocols:
        t0 = time.time()
        r = _run(fn)
        elapsed = time.time() - t0
        assert elapsed < TIMEOUT, (
            f"{fn.__name__} took {elapsed:.1f}s — exceeds {TIMEOUT}s limit"
        )


# ── Accuracy summary (informational, not a hard assertion) ────────────────────

def test_benchmark_accuracy_informational():
    """
    Compute and print benchmark accuracy.
    Expected: [NSPK=attack, NSL=secure, NSSK=attack, ISO9798=attack,
               STS=attack, MQV=attack]
    Target: >= 5/6 = 83% (≥85% after more protocols added in Phase 2.6)
    """
    cases = [
        (make_nspk,    True,  "NSPK"),
        (make_nsl,     False, "NSL"),
        (make_nssk,    True,  "NSSK"),
        (make_iso9798, True,  "ISO9798"),
        (make_sts,     True,  "STS"),
        (make_mqv,     True,  "MQV"),
    ]
    correct = 0
    print("\n  ─── Benchmark Accuracy ───")
    for fn, expected_attack, name in cases:
        r = _run(fn)
        ok = (r.attack_found == expected_attack)
        correct += int(ok)
        tick = "✓" if ok else "✗"
        print(f"  [{tick}] {name:<10} expected={'ATTACK' if expected_attack else 'SECURE':6} "
              f"got={'ATTACK' if r.attack_found else 'SECURE':6} "
              f"({r.attack_type}, {r.states_visited} states)")

    accuracy = correct / len(cases)
    print(f"\n  Accuracy: {correct}/{len(cases)} = {accuracy:.0%}")
    print(f"  Target:   ≥85%  {'✅ MET' if accuracy >= 0.85 else '⚠️  NOT YET'}")
    # Soft assertion — informational only, won't fail CI
    # Hard assertion will be added in benchmark.py after Phase 2.6
    assert correct >= 4, (
        f"Accuracy too low: {correct}/6. At least 4/6 must pass."
    )
