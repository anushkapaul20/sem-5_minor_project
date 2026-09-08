"""
frontend/pages/1_Protocol_Analyzer.py
======================================
Protocol Analyzer page — the main verification interface.

Users can:
  - Pick a built-in protocol (NSPK, NSL, NSSK, ISO9798, STS, MQV)
  - OR type their own equations in arrow notation
  - See full verification result: attack type, trace, PQC analysis
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
from engine.pqc.pqc_checker   import PQCChecker, RISK_BROKEN, RISK_WEAKENED
from extraction.equation_extractor import EquationExtractor
from extraction.attack_extractor   import AttackExtractor

# ── Page config ────────────────────────────────────────────────────────────────

st.set_page_config(page_title="Protocol Analyzer · QuantumScyther AI", page_icon="🔍", layout="wide")

st.markdown("""
<style>
.result-attack {
    background:#3d1515; border:2px solid #f85149; border-radius:12px;
    padding:20px; margin:16px 0;
}
.result-secure {
    background:#0f2d1a; border:2px solid #3fb950; border-radius:12px;
    padding:20px; margin:16px 0;
}
.result-title { font-size:1.6rem; font-weight:700; margin-bottom:8px; }
.attack-color { color:#f85149; }
.secure-color { color:#3fb950; }
.trace-line {
    font-family:monospace; font-size:0.85rem; padding:4px 0;
    border-bottom:1px solid #21262d; color:#e6edf3;
}
.prop-tag {
    background:#1f2d3d; border:1px solid #388bfd;
    color:#58a6ff; padding:3px 10px; border-radius:20px;
    font-size:0.8rem; margin:2px; display:inline-block;
}
.pqc-broken  { color:#f85149; font-weight:600; }
.pqc-weakened{ color:#e3b341; font-weight:600; }
.pqc-safe    { color:#3fb950; font-weight:600; }
</style>
""", unsafe_allow_html=True)

# ── Registry ───────────────────────────────────────────────────────────────────

PROTOCOLS = {
    "NSPK — Needham-Schroeder Public Key (MITM vulnerable)": ("NSPK", make_nspk),
    "NSL  — Needham-Schroeder-Lowe  (Lowe's SECURE fix)":   ("NSL",  make_nsl),
    "NSSK — Needham-Schroeder Symmetric Key (Replay)":       ("NSSK", make_nssk),
    "ISO9798 — ISO/IEC 9798-2 style (Reflection)":           ("ISO9798", make_iso9798),
    "STS — Station-to-Station (UKS)":                        ("STS",  make_sts),
    "MQV — Menezes-Qu-Vanstone (KCI)":                       ("MQV",  make_mqv),
    "✏️  Custom protocol (enter equations below)":            ("CUSTOM", None),
}

PRIM_MAP = {
    "NSPK":    ["Public_Key_Encryption", "Nonce"],
    "NSL":     ["Public_Key_Encryption", "Nonce"],
    "NSSK":    ["Symmetric_Encryption", "Nonce", "Session_Key", "Shared_Secret"],
    "ISO9798": ["Symmetric_Encryption", "Nonce", "Shared_Secret", "Challenge_Response"],
    "STS":     ["Diffie-Hellman", "Digital_Signature", "Certificate", "Symmetric_Encryption", "Session_Key"],
    "MQV":     ["Diffie-Hellman", "Hash", "Session_Key", "Shared_Secret"],
}

EXAMPLE_EQNS = {
    "NSPK":    "A → B : {Na, A}Kb\nB → A : {Na, Nb}Ka\nA → B : {Nb}Kb",
    "NSL":     "A → B : {Na, A}Kb\nB → A : {Na, Nb, B}Ka\nA → B : {Nb}Kb",
    "NSSK":    "A → S : A, B, Na\nS → A : {Na, B, K_AB, {K_AB, A}K_BS}K_AS\nA → B : {K_AB, A}K_BS\nB → A : {Nb}K_AB\nA → B : {Nb}K_AB",
    "ISO9798": "A → B : A, Na\nB → A : {Na}K_AB, Nb\nA → B : {Nb}K_AB",
    "STS":     "A → B : g^x\nB → A : g^y, Cert_B, {sig_B(g^y || g^x)}K\nA → B : Cert_A, {sig_A(g^x || g^y)}K",
    "MQV":     "A → B : X = g^x\nB → A : Y = g^y\nK = H((Y * B^h(Y))^(x + h(X)*a) mod q)",
}

pqc_checker  = PQCChecker()
eq_extractor = EquationExtractor()
atk_extractor= AttackExtractor()

# ── Layout ─────────────────────────────────────────────────────────────────────

st.title("🔍 Protocol Analyzer")
st.markdown("Enter a cryptographic protocol and verify it for security attacks.")

# Sidebar — protocol selector
with st.sidebar:
    st.markdown("### Select Protocol")
    selection = st.selectbox(
        "Protocol",
        list(PROTOCOLS.keys()),
        label_visibility="collapsed",
    )
    short_name, factory = PROTOCOLS[selection]

    st.markdown("---")
    st.markdown("### Attacker Model")
    st.markdown("""
**Dolev-Yao**
- Controls entire network
- Can intercept, modify, replay
- Cannot break encryption without key
- Cannot invert hash
- Cannot solve discrete log
    """)

    st.markdown("---")
    st.markdown("### Session Bound")
    st.markdown("Max **2 concurrent sessions** per role")

# ── Equation input ─────────────────────────────────────────────────────────────

col_left, col_right = st.columns([3, 2])

with col_left:
    st.markdown("#### Protocol Equations")

    # Pre-fill example equations
    default_eqns = ""
    if short_name != "CUSTOM" and short_name in EXAMPLE_EQNS:
        default_eqns = EXAMPLE_EQNS[short_name]

    equations = st.text_area(
        "Equations",
        value=default_eqns,
        height=180,
        placeholder="A → B : {Na, A}Kb\nB → A : {Na, Nb}Ka\nA → B : {Nb}Kb",
        help="Use arrow notation: A → B : message  (or A -> B : message)",
        label_visibility="collapsed",
    )

    if short_name == "CUSTOM":
        description = st.text_area(
            "Attack description (optional — improves detection)",
            height=80,
            placeholder="e.g. man-in-the-middle attack where attacker intercepts messages...",
        )
    else:
        description = ""

    verify_btn = st.button("⚡ Verify Protocol", type="primary", use_container_width=True)

with col_right:
    st.markdown("#### What the engine checks")
    checkers_info = {
        "🔐 Secrecy": "Is a secret term derivable by the attacker?",
        "🔑 Authentication": "Does responder's run match an initiator run?",
        "🔄 Replay": "Is an old message accepted in a new session?",
        "🪞 Reflection": "Is a message bounced back to its sender?",
        "🕵️ MITM": "Can attacker sit between both parties?",
        "🔀 UKS": "Same key, different partner beliefs?",
        "🏷️ Cert. Subst.": "Was the peer certificate substituted?",
        "💥 KCI": "Does key compromise allow impersonation?",
    }
    for name, desc in checkers_info.items():
        st.markdown(f"**{name}** — {desc}")

# ── Run verification ────────────────────────────────────────────────────────────

if verify_btn:
    if not equations.strip():
        st.error("Please enter protocol equations.")
        st.stop()

    with st.spinner("Running verification engine..."):
        t0 = time.time()

        if short_name != "CUSTOM" and factory is not None:
            # Full symbolic engine
            protocol = factory()
            explorer = Explorer(max_sessions=2, timeout_seconds=25)
            result   = explorer.verify(protocol)
            is_engine_result = True
            primitives = PRIM_MAP.get(short_name, [])
        else:
            # Keyword path
            is_engine_result = False
            primitives = eq_extractor.identify_primitives(equations)
            kw = atk_extractor.extract_attack_info(equations + "\n" + description)

            class _FakeResult:
                attack_found   = bool(kw.get("attack_present"))
                attack_type    = ", ".join(kw.get("attack_category", ["None"]))
                property       = ", ".join(kw.get("security_property_targeted", []))
                trace          = kw.get("attack_trace", "").splitlines()
                explanation    = f"Keyword detection only. Confidence: {kw.get('confidence','NONE')}"
                states_visited = 0
                time_seconds   = time.time() - t0

            result = _FakeResult()

        elapsed = time.time() - t0

    # ── Result card ────────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("## Verification Result")

    if result.attack_found:
        res_class = "result-attack"
        icon  = "❌"
        label = "ATTACK FOUND"
        color_class = "attack-color"
    else:
        res_class = "result-secure"
        icon  = "✅"
        label = "SECURE (within bounded model)"
        color_class = "secure-color"

    st.markdown(f"""
    <div class="{res_class}">
        <div class="result-title {color_class}">{icon} &nbsp; {label}</div>
        <b>Protocol:</b> {short_name if short_name != "CUSTOM" else "Custom"} &nbsp;|&nbsp;
        <b>Attack type:</b> {result.attack_type} &nbsp;|&nbsp;
        <b>Property:</b> {result.property or "—"} &nbsp;|&nbsp;
        <b>States visited:</b> {result.states_visited} &nbsp;|&nbsp;
        <b>Time:</b> {elapsed:.2f}s
        {"<br><br><i>Note: 2-session bounded verifier — not a proof of security.</i>" if not result.attack_found else ""}
        {"<br><br><i>⚠️ Keyword-based detection only (custom protocol).</i>" if not is_engine_result else ""}
    </div>
    """, unsafe_allow_html=True)

    # ── Columns: trace + properties ────────────────────────────────────────
    col_trace, col_props = st.columns([3, 2])

    with col_trace:
        if result.attack_found and result.trace:
            st.markdown("#### 🗂️ Attack Trace")
            trace_html = ""
            for line in result.trace:
                if line.strip():
                    icon_t = "📤" if "SEND" in line.upper() else ("📥" if "RECV" in line.upper() else "•")
                    trace_html += f'<div class="trace-line">{icon_t} {line}</div>'
            st.markdown(trace_html, unsafe_allow_html=True)

            if result.explanation:
                st.markdown("#### 💡 Why This Attack Works")
                st.info(result.explanation)
        elif not result.attack_found:
            st.markdown("#### ✅ No Attack Found")
            st.success(
                "The engine explored all reachable states within 2 concurrent sessions "
                "and found no violation of any security property. "
                f"States explored: {result.states_visited}."
            )

    with col_props:
        st.markdown("#### 📐 Parsed Messages")
        msgs = eq_extractor.extract(equations)
        if msgs:
            for m in msgs:
                prot_icon = {"public_key_encryption":"🔏","symmetric_encryption":"🔒",
                             "hash":"#️⃣","diffie-hellman":"🔢","plaintext":"📄"}.get(
                    m.protection, "📦")
                st.markdown(
                    f"**Step {m.step}:** `{m.sender} → {m.receiver}` {prot_icon}"
                )
                st.caption(f"`{m.message}`")
        else:
            st.info("No arrow-notation messages detected.")

        if primitives:
            st.markdown("#### 🧰 Detected Primitives")
            for p in primitives:
                st.markdown(f"• `{p}`")

    # ── PQC Analysis ───────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("## 🌍 Post-Quantum Analysis")
    st.caption("Based on NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)")

    if primitives:
        pqc_results = pqc_checker.check(primitives)
        cols = st.columns(min(len(primitives), 4))
        for i, r in enumerate(pqc_results):
            with cols[i % 4]:
                if r.risk == RISK_BROKEN:
                    st.error(f"**{r.primitive}**\n\n🔴 BROKEN\n\n{r.threat}")
                    st.caption(f"Replace with: {r.replacement}")
                elif r.risk == RISK_WEAKENED:
                    st.warning(f"**{r.primitive}**\n\n⚠️ WEAKENED\n\n{r.threat}")
                    st.caption(f"Upgrade to: {r.replacement}")
                else:
                    st.success(f"**{r.primitive}**\n\n✅ SAFE")
    else:
        st.info("No primitives detected — enter equations to enable PQC analysis.")

    # ── ML Prediction ─────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("## 🤖 ML Model Prediction")
    st.caption("TF-IDF + Logistic Regression (Model A) · TF-IDF + Random Forest (Model B) · Trained on 11 papers")

    try:
        from models.training.train_baseline import predict, serialise_record
        pseudo = {
            "protocol_name":           short_name if short_name != "CUSTOM" else "Custom",
            "protocol_type":           "authentication",
            "participants":            ["A", "B"],
            "trusted_third_party":     False,
            "cryptographic_primitives": primitives,
            "original_equations":      equations,
            "message_step_count":      len(msgs),
            "attacker_model":          "Dolev-Yao",
            "attacker_capabilities":   ["intercept", "forward", "impersonate"],
            "security_property_targeted": [],
        }
        feat = serialise_record(pseudo, include_attack_name=False)
        ml_result = predict(feat, dataset_version="v1")

        if "error" in ml_result:
            st.warning(ml_result["error"])
        else:
            c1, c2, c3 = st.columns(3)
            with c1:
                if ml_result["attack_present"] == 1:
                    st.error(f"**ML says: ATTACK** ({ml_result['confidence_binary']:.0%} conf)")
                else:
                    st.success(f"**ML says: SECURE** ({ml_result['confidence_binary']:.0%} conf)")
            with c2:
                st.info(f"**Predicted category:** {ml_result['attack_category']}")
            with c3:
                st.info(f"**Category confidence:** {ml_result['confidence_multi']:.0%}")
            st.caption(
                "⚠️ **ML-based prediction** — trained on 11 papers (indicative only). "
                "The formal engine result above is more reliable."
            )
    except Exception as ex:
        st.info(f"ML model not available: {ex}")

    # ── Method label ────────────────────────────────────────────────────────
    st.markdown("---")
    if is_engine_result:
        st.caption("🔬 **Formal verification result** — produced by the custom Dolev-Yao symbolic engine")
    else:
        st.caption("🔤 **Keyword-based detection** — NOT formal verification. Use a built-in protocol for engine analysis.")
