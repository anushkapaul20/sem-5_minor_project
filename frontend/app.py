"""
frontend/app.py
===============
QuantumScyther AI — Main Streamlit Dashboard

Run with:
    cd cryptographic_protocol_attack_detection
    streamlit run frontend/app.py

Pages:
    1  Protocol Analyzer    — input protocol, get full verification result
    2  Dataset Explorer     — browse dataset_v0 records
    3  PQC Checker          — check primitives for quantum vulnerability
    4  Engine Benchmark     — run and display live benchmark results
"""

import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ── Page config ────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="QuantumScyther AI",
    page_icon="⚛️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────

st.markdown("""
<style>
/* Sidebar */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0d1117 0%, #161b22 100%);
}
[data-testid="stSidebar"] * { color: #e6edf3 !important; }

/* Header banner */
.qs-header {
    background: linear-gradient(135deg, #0d1117, #1a2744);
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 24px 32px;
    margin-bottom: 24px;
}
.qs-title {
    font-size: 2.4rem;
    font-weight: 700;
    color: #58a6ff;
    margin: 0;
}
.qs-subtitle {
    font-size: 1.0rem;
    color: #8b949e;
    margin-top: 6px;
}

/* Cards */
.metric-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 20px;
    text-align: center;
}
.metric-value { font-size: 2rem; font-weight: 700; color: #58a6ff; }
.metric-label { font-size: 0.85rem; color: #8b949e; margin-top: 4px; }

/* Attack badge */
.badge-attack {
    background: #3d1515; border: 1px solid #f85149;
    color: #f85149; padding: 4px 12px; border-radius: 20px;
    font-weight: 600; font-size: 0.9rem; display: inline-block;
}
.badge-secure {
    background: #0f2d1a; border: 1px solid #3fb950;
    color: #3fb950; padding: 4px 12px; border-radius: 20px;
    font-weight: 600; font-size: 0.9rem; display: inline-block;
}
.badge-pqc-broken {
    background: #3d1515; border: 1px solid #f85149;
    color: #f85149; padding: 3px 10px; border-radius: 4px; font-size: 0.8rem;
}
.badge-pqc-weakened {
    background: #2d1f00; border: 1px solid #e3b341;
    color: #e3b341; padding: 3px 10px; border-radius: 4px; font-size: 0.8rem;
}
.badge-pqc-safe {
    background: #0f2d1a; border: 1px solid #3fb950;
    color: #3fb950; padding: 3px 10px; border-radius: 4px; font-size: 0.8rem;
}

/* Trace box */
.trace-box {
    background: #0d1117; border: 1px solid #30363d;
    border-radius: 8px; padding: 16px;
    font-family: 'Courier New', monospace; font-size: 0.85rem;
    color: #e6edf3; white-space: pre-wrap;
}

/* Section divider */
.section-header {
    border-left: 3px solid #58a6ff;
    padding-left: 12px; margin: 20px 0 12px 0;
    font-weight: 600; font-size: 1.1rem; color: #e6edf3;
}
</style>
""", unsafe_allow_html=True)

# ── Header ─────────────────────────────────────────────────────────────────────

st.markdown("""
<div class="qs-header">
    <div class="qs-title">⚛️ QuantumScyther AI</div>
    <div class="qs-subtitle">
        AI-Powered Cryptographic Protocol Verification with Post-Quantum Awareness
        &nbsp;|&nbsp; B.Tech Minor Project &nbsp;|&nbsp; Semester 5
    </div>
</div>
""", unsafe_allow_html=True)

# ── Overview metrics ───────────────────────────────────────────────────────────

col1, col2, col3, col4, col5 = st.columns(5)
metrics = [
    ("6",    "Protocol Records"),
    ("5/6",  "Engine Accuracy"),
    ("232",  "Tests Passing"),
    ("10",   "Attack Categories"),
    ("3",    "NIST PQC Standards"),
]
for col, (val, label) in zip([col1, col2, col3, col4, col5], metrics):
    with col:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{val}</div>
            <div class="metric-label">{label}</div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("---")

# ── Navigation guide ───────────────────────────────────────────────────────────

st.markdown("### 🧭 Navigate using the sidebar")

c1, c2 = st.columns(2)
with c1:
    st.markdown("""
**📋 Protocol Analyzer**
Enter any cryptographic protocol in arrow notation and get a full security analysis —
attack detection, attack trace, violated properties, and post-quantum assessment.

**📊 Dataset Explorer**
Browse all 6 verified protocol records in the benchmark dataset.
View equations, attack traces, source papers, and cryptographic primitives.
    """)
with c2:
    st.markdown("""
**🔐 PQC Checker**
Select cryptographic primitives and see which ones are broken by
Shor's algorithm, weakened by Grover's algorithm, and what NIST FIPS
203/204/205 replaces them with.

**⚡ Engine Benchmark**
Run the Dolev-Yao verification engine live against all 6 benchmark protocols
and see the accuracy results in real time.
    """)

# ── Architecture diagram ────────────────────────────────────────────────────────

with st.expander("🏗️ System Architecture", expanded=False):
    st.code("""
User Input  (Arrow notation: A → B : {Na,A}Kb)
        │
        ▼
┌─────────────────────────────────────────────────┐
│      Equation Extractor  +  Attack Extractor     │
│      (keyword-based detection for custom input)  │
└────────────────────┬────────────────────────────┘
                     │  (for built-in protocols)
        ▼
┌─────────────────────────────────────────────────┐
│        Custom Dolev-Yao Verification Engine      │
│                                                  │
│  Term Algebra  →  Attacker Model  →  BFS Search  │
│  Bounded 2-session model checker                 │
│  8 Property Checkers:                            │
│    Secrecy · Auth · Replay · Reflection          │
│    MITM · UKS · Cert-Substitution · KCI          │
└────────────────────┬────────────────────────────┘
                     │
        ▼
┌─────────────────────────────────────────────────┐
│  PQC Flagging                                    │
│  Classical Primitive → Shor/Grover threat →     │
│  NIST FIPS 203/204/205 replacement              │
└─────────────────────────────────────────────────┘
    """, language=None)

st.markdown("---")
st.caption("QuantumScyther AI v0.3 · 2026 · B.Tech Minor Project")
