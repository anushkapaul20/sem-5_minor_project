"""
frontend/pages/3_PQC_Checker.py
=================================
Post-Quantum Cryptography Checker page.
"""

import sys
from pathlib import Path
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from engine.pqc.pqc_checker import PQCChecker, RISK_BROKEN, RISK_WEAKENED, RISK_SAFE

st.set_page_config(page_title="PQC Checker · QuantumScyther AI", page_icon="🔐", layout="wide")

st.markdown("""
<style>
.pqc-card-broken {
    background:#1e0f0f; border:2px solid #f85149;
    border-radius:10px; padding:16px; margin-bottom:12px;
}
.pqc-card-weakened {
    background:#1e1600; border:2px solid #e3b341;
    border-radius:10px; padding:16px; margin-bottom:12px;
}
.pqc-card-safe {
    background:#0f1e14; border:2px solid #3fb950;
    border-radius:10px; padding:16px; margin-bottom:12px;
}
.pqc-prim  { font-size:1.1rem; font-weight:700; }
.pqc-threat{ font-size:0.85rem; color:#8b949e; margin-top:4px; }
.fips-tag  {
    background:#1f2d3d; border:1px solid #388bfd; color:#58a6ff;
    padding:2px 8px; border-radius:4px; font-size:0.78rem;
    margin:2px; display:inline-block;
}
</style>
""", unsafe_allow_html=True)

checker = PQCChecker()

ALL_PRIMITIVES = [
    "RSA", "Diffie-Hellman", "ECDH", "ECC", "Digital_Signature",
    "Public_Key_Encryption", "Certificate",
    "AES", "3DES", "DES", "Symmetric_Encryption",
    "Hash", "HMAC", "MAC",
    "Nonce", "Timestamp", "Session_Key", "Shared_Secret",
    "Password", "Challenge_Response",
]

st.title("🔐 Post-Quantum Cryptography Checker")
st.markdown("""
Select the cryptographic primitives used in your protocol and see which ones are
threatened by quantum computing — and what NIST-standardised replacements exist.

**Standards referenced:** NIST FIPS 203 (ML-KEM) · FIPS 204 (ML-DSA) · FIPS 205 (SLH-DSA) · August 2024
""")

# Quick presets
with st.sidebar:
    st.markdown("### Quick Presets")
    preset = st.radio(
        "Protocol preset",
        ["None", "NSPK / NSL", "NSSK / Kerberos", "STS / DH-based", "MQV", "TLS-RSA", "Signal (X3DH)"],
        label_visibility="collapsed",
    )
    PRESETS = {
        "NSPK / NSL":       ["Public_Key_Encryption", "Nonce"],
        "NSSK / Kerberos":  ["Symmetric_Encryption", "Nonce", "Session_Key", "Shared_Secret"],
        "STS / DH-based":   ["Diffie-Hellman", "Digital_Signature", "Certificate", "Symmetric_Encryption", "Session_Key"],
        "MQV":              ["Diffie-Hellman", "Hash", "Session_Key", "Shared_Secret"],
        "TLS-RSA":          ["RSA", "Symmetric_Encryption", "Hash", "Certificate", "Session_Key"],
        "Signal (X3DH)":    ["ECDH", "Hash", "Session_Key", "Symmetric_Encryption"],
    }

    st.markdown("---")
    st.markdown("### Quantum Threats")
    st.error("**Shor's algorithm**\nBreaks RSA, DH, ECDH, ECC, DSA completely")
    st.warning("**Grover's algorithm**\nHalves effective key length of symmetric/hash")

# Default selection from preset
default_selection = PRESETS.get(preset, [])

selected = st.multiselect(
    "Select primitives to check",
    ALL_PRIMITIVES,
    default=default_selection,
    help="Select all primitives used in your protocol",
)

if not selected:
    st.info("👆 Select primitives above or choose a preset from the sidebar.")
    st.stop()

results = checker.check(selected)

# Summary row
broken   = [r for r in results if r.risk == RISK_BROKEN]
weakened = [r for r in results if r.risk == RISK_WEAKENED]
safe     = [r for r in results if r.risk == RISK_SAFE]

c1, c2, c3 = st.columns(3)
with c1: st.error(f"🔴 **{len(broken)} BROKEN** by Shor's algorithm")
with c2: st.warning(f"⚠️ **{len(weakened)} WEAKENED** by Grover's algorithm")
with c3: st.success(f"✅ **{len(safe)} SAFE** — no known quantum vulnerability")

st.markdown("---")

# Per-primitive cards
if broken:
    st.markdown("### 🔴 BROKEN — Replace Immediately")
    cols = st.columns(min(len(broken), 3))
    for i, r in enumerate(broken):
        with cols[i % 3]:
            fips_html = " ".join(f'<span class="fips-tag">{f}</span>' for f in r.fips)
            st.markdown(f"""
            <div class="pqc-card-broken">
                <div class="pqc-prim" style="color:#f85149">🔴 {r.primitive}</div>
                <div class="pqc-threat">{r.threat}</div>
                <div style="margin-top:8px;font-size:0.85rem;color:#e6edf3">
                    <b>Replace with:</b><br>{r.replacement}
                </div>
                <div style="margin-top:8px">{fips_html}</div>
            </div>
            """, unsafe_allow_html=True)

if weakened:
    st.markdown("### ⚠️ WEAKENED — Upgrade for Long-Term Security")
    cols = st.columns(min(len(weakened), 3))
    for i, r in enumerate(weakened):
        with cols[i % 3]:
            note_text = f"<br><i>{r.note}</i>" if r.note else ""
            st.markdown(f"""
            <div class="pqc-card-weakened">
                <div class="pqc-prim" style="color:#e3b341">⚠️ {r.primitive}</div>
                <div class="pqc-threat">{r.threat}</div>
                <div style="margin-top:8px;font-size:0.85rem;color:#e6edf3">
                    <b>Upgrade to:</b><br>{r.replacement}{note_text}
                </div>
            </div>
            """, unsafe_allow_html=True)

if safe:
    st.markdown("### ✅ SAFE — No Quantum Vulnerability")
    safe_html = " &nbsp; ".join(
        f'<span style="background:#0f2d1a;border:1px solid #3fb950;color:#3fb950;'
        f'padding:4px 12px;border-radius:20px;font-size:0.85rem">✅ {r.primitive}</span>'
        for r in safe
    )
    st.markdown(safe_html, unsafe_allow_html=True)

# NIST Standards reference
st.markdown("---")
with st.expander("📋 NIST PQC Standards Reference", expanded=False):
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("""
**FIPS 203 — ML-KEM**
Module-Lattice Key Encapsulation
- Replaces: RSA, DH, ECDH
- Based on: MLWE problem
- Sizes: 512 / 768 / 1024
        """)
    with c2:
        st.markdown("""
**FIPS 204 — ML-DSA**
Module-Lattice Digital Signatures
- Replaces: RSA-sign, ECDSA, DSA
- Based on: MLWE + MSIS
- Sizes: 44 / 65 / 87
        """)
    with c3:
        st.markdown("""
**FIPS 205 — SLH-DSA**
Stateless Hash-Based Signatures
- Replaces: RSA signatures (conservative)
- Based on: hash function only
- Advantage: minimal assumptions
        """)
