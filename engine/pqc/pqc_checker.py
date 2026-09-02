"""
engine/pqc/pqc_checker.py
==========================
Post-Quantum Cryptography checker for QuantumScyther AI.

Given a list of cryptographic primitives found in a protocol,
this module flags which ones are vulnerable to quantum attacks
and provides the NIST PQC replacement recommendation.

Sources
-------
- NIST FIPS 203 (ML-KEM), August 2024
- NIST FIPS 204 (ML-DSA), August 2024
- NIST FIPS 205 (SLH-DSA), August 2024
- Shor, P.W. (1994). Algorithms for quantum computation.
- Grover, L.K. (1996). A fast quantum mechanical algorithm.

Usage
-----
    from engine.pqc.pqc_checker import PQCChecker

    checker = PQCChecker()
    results = checker.check(["RSA", "Nonce", "AES", "ECDH"])
    for r in results:
        print(r.primitive, r.risk, r.replacement)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ── Risk levels ───────────────────────────────────────────────────────────────

RISK_BROKEN   = "BROKEN"    # Completely broken by Shor's algorithm
RISK_WEAKENED = "WEAKENED"  # Security halved by Grover's algorithm
RISK_SAFE     = "SAFE"      # No known quantum vulnerability


# ── PQC Lookup Table ──────────────────────────────────────────────────────────
# Sources: NIST FIPS 203/204/205 (August 2024), Shor 1994, Grover 1996

_PQC_TABLE: Dict[str, dict] = {

    # ── BROKEN by Shor ────────────────────────────────────────────────────────
    "RSA": {
        "risk":        RISK_BROKEN,
        "threat":      "Shor's algorithm",
        "reason":      "RSA security relies on integer factoring, which Shor's algorithm solves in polynomial time on a quantum computer.",
        "replacement": "ML-KEM (FIPS 203) for key encapsulation; ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures",
        "fips":        ["FIPS 203", "FIPS 204", "FIPS 205"],
    },
    "Diffie-Hellman": {
        "risk":        RISK_BROKEN,
        "threat":      "Shor's algorithm",
        "reason":      "Finite-field DH security relies on the discrete logarithm problem, solved by Shor's algorithm.",
        "replacement": "ML-KEM (FIPS 203)",
        "fips":        ["FIPS 203"],
    },
    "ECDH": {
        "risk":        RISK_BROKEN,
        "threat":      "Shor's algorithm",
        "reason":      "Elliptic curve DH security relies on the elliptic curve discrete log problem (ECDLP), solved by Shor's algorithm.",
        "replacement": "ML-KEM (FIPS 203)",
        "fips":        ["FIPS 203"],
    },
    "ECC": {
        "risk":        RISK_BROKEN,
        "threat":      "Shor's algorithm",
        "reason":      "All elliptic curve cryptography relying on ECDLP is broken by Shor's algorithm.",
        "replacement": "ML-KEM (FIPS 203) for key exchange; ML-DSA (FIPS 204) for signatures",
        "fips":        ["FIPS 203", "FIPS 204"],
    },
    "Digital_Signature": {
        "risk":        RISK_BROKEN,
        "threat":      "Shor's algorithm",
        "reason":      "Classical digital signatures (RSA-sign, ECDSA, DSA) rely on factoring or DLP — both broken by Shor.",
        "replacement": "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)",
        "fips":        ["FIPS 204", "FIPS 205"],
    },
    "Public_Key_Encryption": {
        "risk":        RISK_BROKEN,
        "threat":      "Shor's algorithm",
        "reason":      "RSA/ECC-based public-key encryption is broken by Shor's algorithm.",
        "replacement": "ML-KEM (FIPS 203)",
        "fips":        ["FIPS 203"],
    },
    "Certificate": {
        "risk":        RISK_BROKEN,
        "threat":      "Shor's algorithm (via signature algorithm)",
        "reason":      "X.509 certificates rely on RSA or ECDSA signatures, both broken by Shor. Certificates must be re-issued with PQC signing keys.",
        "replacement": "Re-issue with ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) signing keys",
        "fips":        ["FIPS 204", "FIPS 205"],
    },

    # ── BROKEN classically + further weakened by Grover ───────────────────────
    "DES": {
        "risk":        RISK_BROKEN,
        "threat":      "Classically broken + Grover's algorithm",
        "reason":      "DES is already broken classically (56-bit key). Grover halves effective bits further. Must be replaced immediately.",
        "replacement": "AES-256",
        "fips":        [],
    },
    "3DES": {
        "risk":        RISK_BROKEN,
        "threat":      "Legacy + Grover's algorithm",
        "reason":      "3DES has known weaknesses (Sweet32 attack) and is deprecated. Grover further reduces its security.",
        "replacement": "AES-256",
        "fips":        [],
    },

    # ── WEAKENED by Grover ────────────────────────────────────────────────────
    "AES": {
        "risk":        RISK_WEAKENED,
        "threat":      "Grover's algorithm",
        "reason":      "Grover's algorithm provides a quadratic speedup for brute-force key search. AES-128 effective security drops to ~64 bits. AES-256 drops to ~128 bits (acceptable).",
        "replacement": "Use AES-256 for long-term security. AES-128 acceptable for near-term only.",
        "fips":        [],
        "note":        "AES-256 is quantum-safe at 128-bit security level.",
    },
    "Hash": {
        "risk":        RISK_WEAKENED,
        "threat":      "Grover's algorithm",
        "reason":      "Grover halves the effective collision resistance. SHA-256 drops from 128-bit to ~85-bit collision resistance under quantum attack.",
        "replacement": "SHA-512 or SHA3-512 for long-term use. SHA-256 acceptable for near-term.",
        "fips":        [],
    },
    "HMAC": {
        "risk":        RISK_WEAKENED,
        "threat":      "Grover's algorithm (via underlying hash)",
        "reason":      "HMAC security depends on the underlying hash function, which is weakened by Grover.",
        "replacement": "HMAC-SHA512",
        "fips":        [],
    },
    "MAC": {
        "risk":        RISK_WEAKENED,
        "threat":      "Grover's algorithm",
        "reason":      "MAC security depends on key and output size. Grover halves effective key search.",
        "replacement": "Increase to ≥256-bit keys; prefer HMAC-SHA512 or KMAC.",
        "fips":        [],
    },
    "Symmetric_Encryption": {
        "risk":        RISK_WEAKENED,
        "threat":      "Grover's algorithm",
        "reason":      "Grover's algorithm halves effective symmetric key length. 128-bit → ~64-bit security under quantum attack.",
        "replacement": "Use AES-256 or ChaCha20-256",
        "fips":        [],
    },
    "Shared_Secret": {
        "risk":        RISK_WEAKENED,
        "threat":      "Grover's algorithm (if short)",
        "reason":      "Short shared secrets become vulnerable under Grover's quadratic speedup.",
        "replacement": "Use ≥256-bit shared secrets derived via ML-KEM",
        "fips":        ["FIPS 203"],
    },
    "Session_Key": {
        "risk":        RISK_WEAKENED,
        "threat":      "Grover's algorithm",
        "reason":      "Session keys shorter than 256 bits have reduced quantum security.",
        "replacement": "Derive session keys from ML-KEM (FIPS 203); use ≥256 bits",
        "fips":        ["FIPS 203"],
    },
    "Password": {
        "risk":        RISK_WEAKENED,
        "threat":      "Grover's algorithm (on KDF/hash)",
        "reason":      "Password hashing relies on hash functions weakened by Grover. Increase work factor.",
        "replacement": "Use Argon2id with higher memory/time cost parameters",
        "fips":        [],
    },

    # ── SAFE ──────────────────────────────────────────────────────────────────
    "Nonce": {
        "risk":        RISK_SAFE,
        "threat":      "None",
        "reason":      "Nonces are freshness mechanisms, not cryptographic primitives. Not vulnerable to quantum attacks.",
        "replacement": "No change needed",
        "fips":        [],
    },
    "Timestamp": {
        "risk":        RISK_SAFE,
        "threat":      "None",
        "reason":      "Timestamps are freshness mechanisms. Not vulnerable to quantum attacks.",
        "replacement": "No change needed",
        "fips":        [],
    },
    "Challenge_Response": {
        "risk":        RISK_SAFE,
        "threat":      "None (mechanism, not primitive)",
        "reason":      "Challenge-response is a protocol mechanism. Update the underlying cryptographic primitive used inside it.",
        "replacement": "No change to the mechanism; update underlying primitive",
        "fips":        [],
    },
}


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class PQCResult:
    """PQC analysis result for one primitive."""
    primitive:   str
    risk:        str            # BROKEN | WEAKENED | SAFE | UNKNOWN
    threat:      str
    reason:      str
    replacement: str
    fips:        List[str]
    note:        str = ""
    known:       bool = True    # False if primitive not in lookup table

    @property
    def is_vulnerable(self) -> bool:
        return self.risk in (RISK_BROKEN, RISK_WEAKENED)

    def report_line(self) -> str:
        icon = {"BROKEN": "🔴", "WEAKENED": "⚠️ ", "SAFE": "✅"}.get(self.risk, "❓")
        return f"  {icon} {self.primitive:<28} {self.risk:<10}  → {self.replacement}"


# ── PQC Checker ────────────────────────────────────────────────────────────────

class PQCChecker:
    """
    Checks a list of cryptographic primitives against the PQC lookup table
    and returns per-primitive results plus a summary report.

    Usage
    -----
        checker = PQCChecker()
        results = checker.check(["RSA", "Nonce", "AES", "ECDH"])
        print(checker.report(results))
    """

    def check(self, primitives: List[str]) -> List[PQCResult]:
        """
        Check each primitive against the lookup table.

        Parameters
        ----------
        primitives : list of str — from the dataset controlled vocabulary

        Returns
        -------
        list of PQCResult, one per input primitive
        """
        results = []
        for prim in primitives:
            entry = _PQC_TABLE.get(prim)
            if entry:
                results.append(PQCResult(
                    primitive=prim,
                    risk=entry["risk"],
                    threat=entry["threat"],
                    reason=entry["reason"],
                    replacement=entry["replacement"],
                    fips=entry.get("fips", []),
                    note=entry.get("note", ""),
                    known=True,
                ))
            else:
                results.append(PQCResult(
                    primitive=prim,
                    risk="UNKNOWN",
                    threat="Unknown",
                    reason=f"Primitive '{prim}' not found in PQC lookup table. Manual review required.",
                    replacement="REQUIRES_MANUAL_VERIFICATION",
                    fips=[],
                    known=False,
                ))
        return results

    def report(self, results: List[PQCResult]) -> str:
        """Generate a formatted PQC analysis report string."""
        broken   = [r for r in results if r.risk == RISK_BROKEN]
        weakened = [r for r in results if r.risk == RISK_WEAKENED]
        safe     = [r for r in results if r.risk == RISK_SAFE]
        unknown  = [r for r in results if r.risk == "UNKNOWN"]

        lines = [
            "",
            "POST-QUANTUM ANALYSIS",
            "─" * 60,
        ]

        if not results:
            lines.append("  No primitives to analyse.")
            return "\n".join(lines)

        if broken:
            lines.append(f"\n  🔴 BROKEN by Shor's algorithm ({len(broken)} primitive(s)):")
            for r in broken:
                lines.append(r.report_line())
                lines.append(f"       Reason : {r.reason}")
                if r.fips:
                    lines.append(f"       FIPS   : {', '.join(r.fips)}")

        if weakened:
            lines.append(f"\n  ⚠️  WEAKENED by Grover's algorithm ({len(weakened)} primitive(s)):")
            for r in weakened:
                lines.append(r.report_line())
                if r.note:
                    lines.append(f"       Note   : {r.note}")

        if safe:
            lines.append(f"\n  ✅ SAFE — no quantum vulnerability ({len(safe)} primitive(s)):")
            for r in safe:
                lines.append(f"     ✅ {r.primitive}")

        if unknown:
            lines.append(f"\n  ❓ UNKNOWN — not in lookup table ({len(unknown)} primitive(s)):")
            for r in unknown:
                lines.append(f"     ❓ {r.primitive} — manual review required")

        lines.append("")
        if broken:
            lines.append("  ⚠️  ACTION REQUIRED: Replace BROKEN primitives before quantum computers arrive.")
        elif weakened:
            lines.append("  ℹ️  Consider upgrading WEAKENED primitives for long-term security.")
        else:
            lines.append("  ✅ No quantum-vulnerable primitives detected.")

        return "\n".join(lines)

    def has_vulnerabilities(self, primitives: List[str]) -> bool:
        """Quick check: does this primitive list contain any quantum-vulnerable entries?"""
        return any(r.is_vulnerable for r in self.check(primitives))


# ── Standalone demo ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    checker = PQCChecker()

    print("=== NSPK (RSA + Nonce) ===")
    r = checker.check(["Public_Key_Encryption", "Nonce"])
    print(checker.report(r))

    print("\n=== STS (DH + Digital Signature + Session Key) ===")
    r = checker.check(["Diffie-Hellman", "Digital_Signature", "Session_Key", "Certificate"])
    print(checker.report(r))

    print("\n=== Symmetric protocol (AES + HMAC + Nonce) ===")
    r = checker.check(["Symmetric_Encryption", "HMAC", "Nonce", "Session_Key"])
    print(checker.report(r))
