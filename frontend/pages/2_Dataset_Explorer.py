"""
frontend/pages/2_Dataset_Explorer.py
=====================================
Dataset Explorer — browse all benchmark records in dataset_v0.
"""

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

st.set_page_config(page_title="Dataset Explorer · QuantumScyther AI", page_icon="📊", layout="wide")

st.markdown("""
<style>
.paper-card {
    background:#161b22; border:1px solid #30363d; border-radius:10px;
    padding:20px; margin-bottom:16px;
}
.paper-title { font-size:1.05rem; font-weight:600; color:#e6edf3; }
.paper-meta  { font-size:0.85rem; color:#8b949e; margin-top:4px; }
.attack-badge {
    background:#3d1515; border:1px solid #f85149; color:#f85149;
    padding:2px 10px; border-radius:20px; font-size:0.8rem;
    font-weight:600; margin-right:6px;
}
.secure-badge {
    background:#0f2d1a; border:1px solid #3fb950; color:#3fb950;
    padding:2px 10px; border-radius:20px; font-size:0.8rem; font-weight:600;
}
.prim-tag {
    background:#1f2d3d; border:1px solid #388bfd; color:#58a6ff;
    padding:2px 8px; border-radius:4px; font-size:0.78rem; margin:2px;
    display:inline-block;
}
</style>
""", unsafe_allow_html=True)

# ── Load dataset ───────────────────────────────────────────────────────────────

@st.cache_data
def load_dataset():
    ds_path = ROOT / "data" / "versions" / "dataset_v0.json"
    if not ds_path.exists():
        return [], {}
    with open(ds_path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("records", []), data.get("metadata", {})


records, meta = load_dataset()

# ── Header ─────────────────────────────────────────────────────────────────────

st.title("📊 Dataset Explorer")
st.markdown("Browse all verified protocol records in **dataset_v0** — every equation traced to its source paper.")

# Summary metrics
c1, c2, c3, c4 = st.columns(4)
with c1: st.metric("Total Records",    meta.get("record_count", len(records)))
with c2: st.metric("Attack Present",   meta.get("attack_present_count", "—"))
with c3: st.metric("Secure",           meta.get("attack_absent_count", "—"))
with c4: st.metric("Human Verified",   sum(1 for r in records if r.get("extraction_status") == "HUMAN_VERIFIED"))

st.markdown("---")

# ── Filters sidebar ────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### Filters")
    attack_filter = st.multiselect(
        "Attack category",
        ["MITM", "Replay", "Reflection", "Impersonation", "UKS",
         "Secrecy_Violation", "Authentication_Violation",
         "Session_Key_Compromise", "KCI", "Forward_Secrecy_Violation", "None"],
        default=[],
    )
    show_only_attacks = st.checkbox("Show only attack records", value=False)
    show_only_secure  = st.checkbox("Show only secure records", value=False)

    st.markdown("---")
    st.markdown("### Download")
    csv_path = ROOT / "data" / "versions" / "dataset_v0.csv"
    if csv_path.exists():
        with open(csv_path, "rb") as f:
            st.download_button(
                "⬇️ Download CSV",
                data=f,
                file_name="dataset_v0.csv",
                mime="text/csv",
                use_container_width=True,
            )

# ── Filter logic ───────────────────────────────────────────────────────────────

filtered = records
if attack_filter:
    filtered = [r for r in filtered
                if any(c in r.get("attack_category", []) for c in attack_filter)]
if show_only_attacks:
    filtered = [r for r in filtered if r.get("attack_present") == 1]
if show_only_secure:
    filtered = [r for r in filtered if r.get("attack_present") == 0]

st.markdown(f"**Showing {len(filtered)} of {len(records)} records**")

# ── Table view ─────────────────────────────────────────────────────────────────

table_data = []
for r in filtered:
    cats = ", ".join(r.get("attack_category", []))
    table_data.append({
        "ID":        r.get("paper_id"),
        "Protocol":  r.get("protocol_name", "")[:45],
        "Attack?":   "⚔️ YES" if r.get("attack_present") else "✅ NO",
        "Category":  cats,
        "Authors":   r.get("authors", "")[:35],
        "Year":      r.get("publication_year"),
        "Steps":     r.get("message_step_count"),
        "Status":    r.get("extraction_status", ""),
    })

if table_data:
    df = pd.DataFrame(table_data)
    st.dataframe(df, use_container_width=True, hide_index=True,
                 column_config={
                     "Attack?": st.column_config.TextColumn(width="small"),
                     "Year":    st.column_config.NumberColumn(format="%d", width="small"),
                     "Steps":   st.column_config.NumberColumn(format="%d", width="small"),
                 })

# ── Detail cards ───────────────────────────────────────────────────────────────

st.markdown("---")
st.markdown("### Record Details")

selected_id = st.selectbox(
    "Select a record to view full details",
    [r.get("paper_id") for r in filtered],
    format_func=lambda x: next(
        (f"{x} — {r.get('protocol_name','')[:50]}" for r in filtered if r.get("paper_id") == x), x
    ),
)

selected = next((r for r in filtered if r.get("paper_id") == selected_id), None)

if selected:
    c_left, c_right = st.columns([3, 2])

    with c_left:
        atk = selected.get("attack_present")
        badge = '<span class="attack-badge">⚔️ ATTACK</span>' if atk else '<span class="secure-badge">✅ SECURE</span>'
        cats  = " ".join(f'<span class="attack-badge">{c}</span>'
                         for c in selected.get("attack_category", []) if c != "None")

        st.markdown(f"""
        <div class="paper-card">
            <div class="paper-title">{selected.get('protocol_name')}</div>
            <div class="paper-meta">
                {selected.get('paper_title')}<br>
                {selected.get('authors')} · {selected.get('publication_year')} · {selected.get('source_type')}
            </div>
            <div style="margin-top:12px">{badge} {cats}</div>
        </div>
        """, unsafe_allow_html=True)

        # Equations
        st.markdown("**Original Equations**")
        eqns = selected.get("original_equations", "")
        st.code(eqns, language=None)

        # Attack trace
        if selected.get("attack_trace"):
            with st.expander("Attack Trace", expanded=True):
                st.text(selected.get("attack_trace"))

    with c_right:
        # Primitives
        prims = selected.get("cryptographic_primitives", [])
        if prims:
            st.markdown("**Cryptographic Primitives**")
            prim_html = " ".join(f'<span class="prim-tag">{p}</span>' for p in prims)
            st.markdown(prim_html, unsafe_allow_html=True)

        st.markdown("**Participants**")
        st.markdown(", ".join(f"`{p}`" for p in selected.get("participants", [])))

        st.markdown("**Message Steps**")
        flow = selected.get("complete_message_flow", [])
        if isinstance(flow, list):
            for step in flow:
                if isinstance(step, dict):
                    st.markdown(
                        f"`{step.get('step','?')}` "
                        f"**{step.get('sender','?')}** → **{step.get('receiver','?')}** : "
                        f"`{step.get('message','?')}`"
                    )

        st.markdown("**Security Properties Targeted**")
        for prop in selected.get("security_property_targeted", []):
            st.markdown(f"• `{prop}`")

        if selected.get("source_link", "").startswith("http"):
            st.markdown(f"**Source:** [{selected.get('source_link')}]({selected.get('source_link')})")

        st.markdown("**Extraction Status**")
        status = selected.get("extraction_status", "")
        if status == "HUMAN_VERIFIED":
            st.success(f"✅ {status}")
        elif status == "REQUIRES_REVIEW":
            st.warning(f"⚠️ {status}")
        else:
            st.info(f"ℹ️ {status}")

        if selected.get("notes"):
            with st.expander("Notes"):
                st.text(selected.get("notes"))
