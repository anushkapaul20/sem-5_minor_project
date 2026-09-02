# PQC GUIDE — Post-Quantum Cryptography Awareness

**Project:** QuantumScyther AI  
**Version:** 0.1  
**Last Updated:** 2026-09-01  
**Standards Referenced:** NIST FIPS 203, FIPS 204, FIPS 205 (August 2024)

---

## Why This Matters

A cryptographic protocol that is secure today may be completely broken once large-scale quantum computers exist. QuantumScyther AI flags any protocol primitive that is known to be vulnerable to quantum attack and maps it to a NIST-standardised Post-Quantum Cryptography (PQC) replacement.

**Two quantum algorithms matter for cryptography:**

| Algorithm | Discovered by | What it breaks | Speed-up |
|-----------|--------------|----------------|---------|
| **Shor's algorithm** | Peter Shor, 1994 | All public-key crypto based on factoring or discrete log (RSA, DH, ECDH, ECC, DSA, ECDSA) | Exponential → Polynomial — completely broken |
| **Grover's algorithm** | Lov Grover, 1996 | Symmetric keys and hash functions | Quadratic — halves effective security bits |

---

## Primitive-by-Primitive Lookup Table

### Group 1 — BROKEN by Shor's Algorithm (replace immediately)

| Primitive | Why Vulnerable | Quantum Attack | NIST Replacement | FIPS Standard |
|-----------|---------------|---------------|-----------------|--------------|
| **RSA** (any key size) | Security based on integer factoring | Shor factors RSA modulus in polynomial time | **ML-KEM** (key encapsulation) or **ML-DSA** (signatures) | FIPS 203 / FIPS 204 |
| **Diffie-Hellman** (finite field, any group) | Security based on discrete log | Shor solves discrete log in polynomial time | **ML-KEM** | FIPS 203 |
| **ECDH / Elliptic Curve Diffie-Hellman** | Security based on elliptic curve discrete log | Shor solves ECDLP in polynomial time | **ML-KEM** | FIPS 203 |
| **ECC** (general elliptic curve operations) | Security based on ECDLP | Shor's algorithm | **ML-KEM** or **ML-DSA** | FIPS 203 / FIPS 204 |
| **DSA** (Digital Signature Algorithm) | Security based on discrete log | Shor's algorithm | **ML-DSA** | FIPS 204 |
| **ECDSA** (Elliptic Curve DSA) | Security based on ECDLP | Shor's algorithm | **ML-DSA** | FIPS 204 |
| **RSA signatures** | Security based on factoring | Shor's algorithm | **SLH-DSA** (stateless hash-based signatures) | FIPS 205 |

---

### Group 2 — WEAKENED by Grover's Algorithm (double key size)

Grover's algorithm provides a quadratic speedup for brute-force search over symmetric keys and hash preimages. A 128-bit key effectively becomes 64-bit security under a quantum attack. The fix is to double the key/output size.

| Primitive | Current Security | Quantum Security | Action Required |
|-----------|-----------------|-----------------|----------------|
| **AES-128** | 128-bit classical | ~64-bit quantum | **Upgrade to AES-256** |
| **AES-192** | 192-bit classical | ~96-bit quantum | **Upgrade to AES-256** |
| **AES-256** | 256-bit classical | ~128-bit quantum | ✅ Acceptable — no change needed |
| **3DES / TDEA** | ~112-bit classical | ~56-bit quantum | **Replace with AES-256** (also legacy) |
| **DES** | 56-bit classical | ~28-bit quantum | **Replace with AES-256** (also broken classically) |
| **SHA-256** | 256-bit classical | ~128-bit quantum | **Upgrade to SHA-384 or SHA-512** for long-term use |
| **SHA-384** | 384-bit classical | ~192-bit quantum | ✅ Acceptable |
| **SHA-512** | 512-bit classical | ~256-bit quantum | ✅ Acceptable |
| **SHA3-256** | 256-bit classical | ~128-bit quantum | **Upgrade to SHA3-384 or SHA3-512** for long-term |
| **SHA3-512** | 512-bit classical | ~256-bit quantum | ✅ Acceptable |
| **HMAC-SHA256** | 256-bit classical | ~128-bit quantum | **Upgrade to HMAC-SHA512** |
| **HMAC-SHA512** | 512-bit classical | ~256-bit quantum | ✅ Acceptable |

---

### Group 3 — UNAFFECTED or MINIMAL IMPACT

| Primitive | Reason | Status |
|-----------|--------|--------|
| **Hash-based signatures** (XMSS, LMS) | Security reduces to hash function hardness | ✅ Quantum-safe (with sufficient hash size) |
| **AES-256** | 128-bit quantum security — acceptable | ✅ No change needed |
| **SHA-512 / SHA3-512** | 256-bit quantum security — acceptable | ✅ No change needed |
| **Nonces / Timestamps** | Not cryptographic primitives; freshness mechanisms | ✅ Unaffected |
| **Certificates** | Only the signature algorithm matters — see Group 1 | Depends on sig algorithm |

---

## NIST PQC Standards (FIPS 2024)

In August 2024, NIST finalised the first three Post-Quantum Cryptography standards:

### FIPS 203 — ML-KEM (Module-Lattice Key Encapsulation Mechanism)

- **Based on:** Module Learning With Errors (MLWE) problem
- **Replaces:** RSA-KEM, ECDH, DH for key exchange / encapsulation
- **Parameter sets:**
  - ML-KEM-512 — NIST Security Level 1 (~AES-128 equivalent)
  - ML-KEM-768 — NIST Security Level 3 (~AES-192 equivalent) ← recommended
  - ML-KEM-1024 — NIST Security Level 5 (~AES-256 equivalent)
- **Use in protocols:** Replace any `{session_key}pk_B` (RSA encryption) or DH key exchange step

### FIPS 204 — ML-DSA (Module-Lattice Digital Signature Algorithm)

- **Based on:** Module Learning With Errors + Module Short Integer Solution
- **Replaces:** ECDSA, DSA, RSA-PSS for digital signatures
- **Parameter sets:**
  - ML-DSA-44 — Security Level 2
  - ML-DSA-65 — Security Level 3 ← recommended
  - ML-DSA-87 — Security Level 5
- **Use in protocols:** Replace any `sig_A(m)` or certificate signature algorithm

### FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)

- **Based on:** Hash function security only (SPHINCS+ design)
- **Replaces:** RSA signatures where a conservative, hash-based approach is preferred
- **Advantage:** Security relies only on hash function hardness — no lattice assumptions needed
- **Trade-off:** Larger signature sizes than ML-DSA
- **Use in protocols:** Long-term signing keys where quantum safety is paramount

---

## How QuantumScyther AI Uses This

When the engine analyses a protocol and identifies cryptographic primitives, the PQC checker (`engine/pqc/pqc_checker.py`) cross-references each primitive against this table and produces a PQC section in the output report:

```
POST-QUANTUM ANALYSIS
─────────────────────
Primitives found in protocol:
  • Public_Key_Encryption (RSA assumed)
  • Nonce

PQC Status:
  ⚠️  Public_Key_Encryption
      Threat  : Shor's algorithm breaks RSA/public-key encryption
      Impact  : Session key can be recovered by quantum attacker
      Fix     : Replace with ML-KEM (NIST FIPS 203)
      Standard: FIPS 203 — ML-KEM-768 recommended

  ✅  Nonce
      No quantum vulnerability — freshness mechanism, not cryptographic primitive
```

---

## Quick Reference Card

```
Quantum Threat → What to Replace → With What
─────────────────────────────────────────────────────────────────
RSA              →  broken by Shor  →  ML-KEM (FIPS 203)
DH / ECDH        →  broken by Shor  →  ML-KEM (FIPS 203)
ECDSA / DSA      →  broken by Shor  →  ML-DSA (FIPS 204)
RSA signatures   →  broken by Shor  →  SLH-DSA (FIPS 205)
AES-128          →  weakened Grover →  AES-256
SHA-256          →  weakened Grover →  SHA-512
3DES / DES       →  broken + Grover →  AES-256
─────────────────────────────────────────────────────────────────
AES-256          →  acceptable      →  no change
SHA-512          →  acceptable      →  no change
Nonce/Timestamp  →  unaffected      →  no change
```

---

## References

1. NIST (2024). **FIPS 203** — Module-Lattice-Based Key-Encapsulation Mechanism Standard. https://doi.org/10.6028/NIST.FIPS.203
2. NIST (2024). **FIPS 204** — Module-Lattice-Based Digital Signature Standard. https://doi.org/10.6028/NIST.FIPS.204
3. NIST (2024). **FIPS 205** — Stateless Hash-Based Digital Signature Standard. https://doi.org/10.6028/NIST.FIPS.205
4. Shor, P.W. (1994). Algorithms for quantum computation: discrete logarithms and factoring. *FOCS 1994.*
5. Grover, L.K. (1996). A fast quantum mechanical algorithm for database search. *STOC 1996.*
6. Bernstein, D.J. & Lange, T. (2017). Post-quantum cryptography. *Nature 549, 188–194.*
