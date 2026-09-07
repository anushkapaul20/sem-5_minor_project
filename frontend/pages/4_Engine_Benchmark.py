"""
frontend/pages/4_Engine_Benchmark.py
======================================
Engine Benchmark page — run live accuracy test against all 6 protocols.
"""

import sys
import time
from pathlib import Path
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from engine.explorer import Explorer
from engine.protocols.nspk    import make_nspk, make_nsl
from engine.protocols.nssk    import make_nssk
from engine.protocols.iso9798 import make_iso9798
from engine.protocols.sts     import make_sts
from engine.protocols.mqv     import make_mqv

st.set_page_config(page_title="Engine Benchmark · QuantumScyther AI", page_icon="⚡", layout="wide")

st.markdown("""
<style>
.bench-row-ok   { background:#0f2d1a; border-left:4px solid #3fb950; padding:12px 16px; border-radius:0 8px 8px 0; margin:4px 0; }
.bench-row-fail { background:#1e0f0f; border-left:4px solid #f85149; padding:12px 16px; border-radius:0 8px 8px 0; margin:4px 0; }
.bench-prot  { font-weight:700; font-size:1rem; color:#e6edf3; }
.bench-meta  { font-size:0.82rem; color:#8b949e; margin-top:4px; }
</style>
""", unsafe_allow_html=True)

CASES = [
    ("NSPK",    True,  make_nspk,    "Needham-Schroeder PKP",    "MITM + Auth Violation"),
    ("NSL",     False, make_nsl,     "Needham-Schroeder-Lowe",   "None (SECURE)"),
    ("NSSK",    True,  make_nssk,    "NS Symmetric Key",         "Replay Attack"),
    ("ISO9798", True,  make_iso9798, "ISO/IEC 9798-2 style",     "Reflection Attack"),
    ("STS",     True,  make_sts,     "Station-to-Station",       "UKS Attack"),
    ("MQV",     True,  make_mqv,     "MQV Key Agreement",        "KCI Attack"),
]

st.title("⚡ Engine Benchmark")
st.markdown("""
Run the **custom Dolev-Yao BFS engine** live against all 6 benchmark protocols
and measure detection accuracy. Target: **≥ 85%** correct verdicts.
""")

col_info, col_run = st.columns([3, 1])
with col_info:
    st.markdown("""
**What this tests:**
Each protocol is verified by the symbolic BFS engine (bounded to 2 concurrent sessions).
The engine checks all 8 security properties and returns the first violation found.
A correct verdict means the engine matches the known expected result from the source paper.
    """)
with col_run:
    run_btn = st.button("▶️ Run Benchmark", type="primary", use_container_width=True)
    timeout = st.number_input("Timeout (s) per protocol", min_value=5, max_value=60, value=25)

st.markdown("---")

# Static table (always shown)
st.markdown("### Expected Results (from source papers)")
cols = st.columns([1.5, 2.5, 1, 2, 2])
cols[0].markdown("**ID**")
cols[1].markdown("**Protocol**")
cols[2].markdown("**Expected**")
cols[3].markdown("**Attack (source paper)**")
cols[4].markdown("**Source**")

paper_info = [
    ("NSPK",    "Needham-Schroeder PKP",  "ATTACK", "MITM",       "Lowe 1996, TACAS"),
    ("NSL",     "Needham-Schroeder-Lowe", "SECURE", "—",          "Lowe 1996, TACAS"),
    ("NSSK",    "NS Symmetric Key",       "ATTACK", "Replay",     "Denning-Sacco 1981"),
    ("ISO9798", "ISO/IEC 9798-2 style",   "ATTACK", "Reflection", "Syverson 1994, CSFW"),
    ("STS",     "Station-to-Station",     "ATTACK", "UKS",        "Blake-Wilson & Menezes 1999"),
    ("MQV",     "MQV Key Agreement",      "ATTACK", "KCI",        "Blake-Wilson et al. 1997"),
]
for pid, pname, exp, atk, src in paper_info:
    c = st.columns([1.5, 2.5, 1, 2, 2])
    c[0].markdown(f"`{pid}`")
    c[1].markdown(pname)
    badge = "⚔️ ATTACK" if exp == "ATTACK" else "✅ SECURE"
    c[2].markdown(badge)
    c[3].markdown(f"`{atk}`" if atk != "—" else "—")
    c[4].caption(src)

# Run benchmark
if run_btn:
    st.markdown("---")
    st.markdown("### 🔬 Live Results")

    explorer = Explorer(max_sessions=2, timeout_seconds=timeout)
    results  = []
    total    = len(CASES)
    correct  = 0

    progress_bar = st.progress(0, text="Starting...")
    result_containers = [st.empty() for _ in CASES]

    for i, (name, expected, factory, full_name, expected_atk) in enumerate(CASES):
        progress_bar.progress((i) / total, text=f"Verifying {name}...")
        t0 = time.time()
        protocol = factory()
        r = explorer.verify(protocol)
        elapsed = time.time() - t0
        ok = r.attack_found == expected
        if ok: correct += 1

        tick      = "✅" if ok else "❌"
        got_label = "ATTACK" if r.attack_found else "SECURE"
        exp_label = "ATTACK" if expected else "SECURE"
        row_class = "bench-row-ok" if ok else "bench-row-fail"

        result_containers[i].markdown(f"""
        <div class="{row_class}">
            <div class="bench-prot">
                {tick} &nbsp; {name} — {full_name}
            </div>
            <div class="bench-meta">
                Expected: <b>{exp_label}</b> &nbsp;|&nbsp;
                Got: <b>{got_label}</b> &nbsp;|&nbsp;
                Type: <b>{r.attack_type}</b> &nbsp;|&nbsp;
                States: {r.states_visited} &nbsp;|&nbsp;
                Time: {elapsed:.2f}s
            </div>
        </div>
        """, unsafe_allow_html=True)

        results.append({
            "name": name, "ok": ok, "got": got_label,
            "type": r.attack_type, "states": r.states_visited, "time": elapsed
        })

    progress_bar.progress(1.0, text="Complete!")

    # Final summary
    accuracy = correct / total
    st.markdown("---")
    st.markdown("### Summary")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Correct", f"{correct}/{total}")
    with c2:
        color = "normal" if accuracy < 0.85 else "off"
        st.metric("Accuracy", f"{accuracy:.0%}", delta=f"Target: 85%" if accuracy < 0.85 else "✅ Target met")
    with c3:
        total_states = sum(r["states"] for r in results)
        st.metric("Total States", f"{total_states:,}")
    with c4:
        total_time = sum(r["time"] for r in results)
        st.metric("Total Time", f"{total_time:.1f}s")

    if accuracy >= 0.85:
        st.success(f"✅ **Accuracy target met!** {correct}/{total} = {accuracy:.0%} ≥ 85%")
    else:
        st.warning(f"⚠️ Accuracy: {correct}/{total} = {accuracy:.0%} — Target: ≥85%")
        failed = [r["name"] for r in results if not r["ok"]]
        st.info(f"Protocols needing fixes: {', '.join(failed)}")

    st.markdown("---")
    st.caption(
        "🔬 **Formal verification** — custom Dolev-Yao BFS engine, 2-session bounded model. "
        "This is not a proof of security — it is a bounded falsification tool."
    )
