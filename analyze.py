"""
analyze.py  —  Interactive Protocol Analyzer (Phase 1A demo)
=============================================================
Run from the project root:
    python analyze.py

You type protocol messages one by one, then the system:
  1. Parses the equations
  2. Detects cryptographic primitives
  3. Detects attack keywords (if you paste a description)
  4. Shows a structured breakdown

This is the Phase 1A extraction engine running live.
The ML model (Phase 3) is not built yet — attack prediction
shown here is keyword-based only and marked clearly as such.
"""

import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from extraction.equation_extractor import EquationExtractor
from extraction.attack_extractor import AttackExtractor

# ── ANSI colours ─────────────────────────────────────────────────────────────
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

BANNER = f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗
║     Cryptographic Protocol Analyzer  — Phase 1A Demo     ║
║     B.Tech Minor Project  |  Anushka Paul                ║
╚══════════════════════════════════════════════════════════╝{RESET}

{DIM}Type protocol messages using arrow notation:
  Example:  A → B : {{Na, A}}Kb
  Example:  B → A : {{Na, Nb}}Ka
  Example:  A → B : g^x

You can also paste a description of the attack to detect it.
Commands:
  {BOLD}analyze{RESET}{DIM}  — parse what you've entered so far
  {BOLD}reset{RESET}{DIM}    — start over
  {BOLD}example{RESET}{DIM}  — load a built-in example (NSPK / NSSK / STS)
  {BOLD}quit{RESET}{DIM}     — exit{RESET}
"""

EXAMPLES = {
    "1": {
        "name": "Needham-Schroeder Public Key Protocol (MITM vulnerable)",
        "messages": [
            "Message 1: A → B : {Na, A}Kb",
            "Message 2: B → A : {Na, Nb}Ka",
            "Message 3: A → B : {Nb}Kb",
        ],
        "description": (
            "A man-in-the-middle attack is possible. The attacker E intercepts "
            "messages and impersonates both parties. Authentication fails because "
            "the peer identity is not bound to the key material."
        ),
    },
    "2": {
        "name": "Needham-Schroeder Symmetric Key (Replay vulnerable)",
        "messages": [
            "Message 1: A → S : A, B, Na",
            "Message 2: S → A : {Na, B, K_AB, {K_AB, A}K_BS}K_AS",
            "Message 3: A → B : {K_AB, A}K_BS",
            "Message 4: B → A : {Nb}K_AB",
            "Message 5: A → B : {Nb - 1}K_AB",
        ],
        "description": (
            "A replay attack is possible. The ticket {K_AB, A}K_BS has no "
            "freshness guarantee. An attacker who intercepts an old ticket and "
            "later learns the old session key can replay it to B."
        ),
    },
    "3": {
        "name": "Station-to-Station (STS) Protocol (UKS vulnerable)",
        "messages": [
            "Step 1: A → B : g^x",
            "Step 2: B → A : g^y, Cert_B, {sig_B(g^y || g^x)}K",
            "Step 3: A → B : Cert_A, {sig_A(g^x || g^y)}K",
        ],
        "description": (
            "An unknown key share attack is demonstrated. The attacker E "
            "substitutes Cert_B with Cert_E. A believes she shares key K "
            "with E, while B believes he shares key K with A. "
            "The key establishment fails because identity is not bound to "
            "the signed data."
        ),
    },
    "4": {
        "name": "Needham-Schroeder-Lowe (NSL) — SECURE FIX",
        "messages": [
            "Message 1: A → B : {Na, A}Kb",
            "Message 2: B → A : {Na, Nb, B}Ka",
            "Message 3: A → B : {Nb}Kb",
        ],
        "description": "This is the Lowe-fixed version. No known attack.",
    },
}


def print_separator(char="─", width=62):
    print(f"{DIM}{char * width}{RESET}")


def parse_and_display(messages_text: str, description: str = "") -> None:
    eq_extractor = EquationExtractor()
    atk_extractor = AttackExtractor()

    # ── Parse messages ────────────────────────────────────────────────────
    messages = eq_extractor.extract(messages_text)

    print(f"\n{BOLD}{GREEN}═══ PARSING RESULT ═══{RESET}")

    if not messages:
        print(f"{YELLOW}  No protocol messages found. Use arrow notation: A → B : payload{RESET}")
        return

    # ── Message flow ──────────────────────────────────────────────────────
    print(f"\n{BOLD}📨  Message Flow{RESET}  ({len(messages)} step{'s' if len(messages)>1 else ''})")
    print_separator()

    for m in messages:
        print(f"  Step {m.step}:  {CYAN}{m.sender} → {m.receiver}{RESET}  :  {BOLD}{m.message}{RESET}")
        print(f"           Protection : {GREEN}{m.protection}{RESET}")
        if m.key:
            print(f"           Key used   : {m.key}")
        if m.payload_items:
            print(f"           Payload    : {m.payload_items}")
        if m.nonces:
            print(f"           Nonces     : {YELLOW}{m.nonces}{RESET}")
        if m.dh_values:
            print(f"           DH values  : {m.dh_values}")
        if m.needs_review:
            print(f"           {YELLOW}⚠  Flagged for review (complex nesting){RESET}")
        print()

    # ── Participants ──────────────────────────────────────────────────────
    participants = {}
    for m in messages:
        for p in (m.sender, m.receiver):
            if p not in participants:
                participants[p] = []
            if m.step not in participants[p]:
                participants[p].append(m.step)

    TTP = {"S", "TTP", "CA", "KDC"}
    non_ttp = [p for p in participants if p not in TTP]
    ttp     = [p for p in participants if p in TTP]

    print(f"{BOLD}👥  Participants{RESET}")
    print_separator()
    for p in sorted(non_ttp):
        print(f"  {CYAN}{p}{RESET}  — appears in steps {participants[p]}")
    for p in sorted(ttp):
        print(f"  {CYAN}{p}{RESET}  — Trusted Third Party, steps {participants[p]}")
    if ttp:
        print(f"  {DIM}(Trusted Third Party present){RESET}")
    print()

    # ── Cryptographic primitives ──────────────────────────────────────────
    detected_prims = eq_extractor.identify_primitives(messages_text)
    print(f"{BOLD}🔐  Cryptographic Primitives Detected{RESET}")
    print_separator()
    if detected_prims:
        for p in detected_prims:
            print(f"  • {GREEN}{p}{RESET}")
    else:
        print(f"  {DIM}None detected automatically — check manually{RESET}")
    print()

    # ── Attack detection (keyword-based) ──────────────────────────────────
    full_text = messages_text + "\n" + description
    attack_info = atk_extractor.extract_attack_info(full_text)

    print(f"{BOLD}🚨  Attack Detection  {DIM}(keyword-based — NOT ML model){RESET}")
    print_separator()

    confidence = attack_info["confidence"]
    colour = {
        "HIGH": RED, "MEDIUM": YELLOW, "LOW": YELLOW, "NONE": GREEN
    }.get(confidence, DIM)

    if attack_info["attack_present"] == 1:
        print(f"  Attack present    : {RED}{BOLD}YES{RESET}")
        print(f"  Confidence        : {colour}{confidence}{RESET}")
        print(f"  Attack categories : {BOLD}{attack_info['attack_category']}{RESET}")
        if attack_info["attacker_capabilities"]:
            print(f"  Attacker can      : {attack_info['attacker_capabilities']}")
        if attack_info["security_property_targeted"]:
            print(f"  Property violated : {RED}{attack_info['security_property_targeted']}{RESET}")
        if attack_info["attack_trace"]:
            print(f"\n  {BOLD}Attack trace lines found:{RESET}")
            for line in attack_info["attack_trace"].splitlines():
                print(f"    {DIM}{line}{RESET}")
    else:
        print(f"  Attack present    : {GREEN}NOT DETECTED{RESET}")
        print(f"  {DIM}No attack keywords found in the input.{RESET}")
        print(f"  {DIM}This does NOT mean the protocol is secure — the ML model{RESET}")
        print(f"  {DIM}(Phase 3) and Scyther (Phase 4) are needed for that.{RESET}")

    print()

    # ── JSON export ───────────────────────────────────────────────────────
    print(f"{BOLD}📋  Structured JSON Output{RESET}")
    print_separator()
    output = {
        "message_step_count": len(messages),
        "participants": sorted(set(p for m in messages for p in (m.sender, m.receiver))),
        "has_trusted_third_party": bool(ttp),
        "cryptographic_primitives": detected_prims,
        "message_flow": [m.to_dict() for m in messages],
        "attack_detection": {
            "method": "keyword-based (NOT ML model — Phase 3 pending)",
            "attack_present": attack_info["attack_present"],
            "confidence": attack_info["confidence"],
            "attack_category": attack_info["attack_category"],
            "attacker_capabilities": attack_info["attacker_capabilities"],
            "security_property_targeted": attack_info["security_property_targeted"],
        },
    }
    print(json.dumps(output, indent=2))
    print()


def load_example(choice: str) -> tuple:
    ex = EXAMPLES.get(choice)
    if not ex:
        return "", ""
    print(f"\n{DIM}Loading: {ex['name']}{RESET}")
    return "\n".join(ex["messages"]), ex["description"]


def main():
    print(BANNER)

    collected_messages = []
    description = ""

    while True:
        try:
            line = input(f"{BOLD}>{RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{DIM}Goodbye.{RESET}")
            break

        if not line:
            continue

        low = line.lower()

        if low == "quit" or low == "exit":
            print(f"{DIM}Goodbye.{RESET}")
            break

        elif low == "reset":
            collected_messages.clear()
            description = ""
            print(f"{GREEN}Reset. Start entering protocol messages.{RESET}")

        elif low == "analyze":
            if not collected_messages:
                print(f"{YELLOW}Nothing entered yet. Type some messages first.{RESET}")
            else:
                full_msg_text = "\n".join(collected_messages)
                parse_and_display(full_msg_text, description)
                print(f"{DIM}(type 'reset' to start over){RESET}")

        elif low == "example":
            print(f"\n{BOLD}Choose an example:{RESET}")
            for k, v in EXAMPLES.items():
                print(f"  {k}) {v['name']}")
            choice = input(f"{BOLD}Enter number:{RESET} ").strip()
            msgs_text, desc = load_example(choice)
            if msgs_text:
                collected_messages = msgs_text.splitlines()
                description = desc
                print(f"{GREEN}Loaded. Type 'analyze' to parse it.{RESET}")
                print(f"\n{DIM}Messages loaded:{RESET}")
                for m in collected_messages:
                    print(f"  {m}")
            else:
                print(f"{YELLOW}Invalid choice.{RESET}")

        elif low.startswith("desc:"):
            # Allow adding attack description: desc: man-in-the-middle attack...
            description = line[5:].strip()
            print(f"{GREEN}Description set.{RESET}")

        else:
            # Treat any other input as a protocol line
            collected_messages.append(line)
            # Check if it looks like an arrow-notation message
            if "→" in line or "->" in line:
                print(f"  {DIM}✓ message added (step {len([l for l in collected_messages if '→' in l or '->' in l])}){RESET}")
            else:
                print(f"  {DIM}✓ line added (use 'analyze' when ready, or 'desc:' prefix for attack descriptions){RESET}")

        if not low in ("quit", "exit", "reset", "analyze", "example"):
            if any("→" in m or "->" in m for m in collected_messages):
                print(f"  {DIM}[{len([l for l in collected_messages if '→' in l or '->' in l])} message(s) entered — type 'analyze' to parse]{RESET}")


if __name__ == "__main__":
    main()
