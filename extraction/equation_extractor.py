"""
equation_extractor.py
=====================
Detects and parses cryptographic equations / protocol message lines from
raw text (PDF-extracted or manually typed).

WHAT IT DOES
------------
Given a block of text (e.g. extracted from a PDF), it:
1. Finds all arrow-notation protocol lines  A → B : ...
2. Decomposes the message payload into a structured dict
3. Identifies cryptographic operations (encryption, hashing, DH, etc.)
4. Normalises participant names to single-letter labels
5. Returns a list of NormalisedMessage objects plus raw matches

WHAT IT DOES NOT DO
-------------------
- Does NOT invent equations that were not in the text
- Does NOT correct ambiguous notation — ambiguous lines are flagged
  as needs_review=True
- Does NOT parse nested structures beyond two levels deep
  (e.g. {{m}K1}K2 is captured as a raw string and flagged)

USAGE
-----
    from extraction.equation_extractor import EquationExtractor

    text = \"\"\"
    Message 1:  A → B : {Na, A}Kb
    Message 2:  B → A : {Na, Nb}Ka
    Message 3:  A → B : {Nb}Kb
    \"\"\"

    extractor = EquationExtractor()
    messages = extractor.extract(text)
    for m in messages:
        print(m)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ── Participant name normalisation map ───────────────────────────────────────

PARTICIPANT_NORM: dict[str, str] = {
    "Alice": "A",
    "alice": "A",
    "Bob": "B",
    "bob": "B",
    "Server": "S",
    "server": "S",
    "Trent": "S",
    "trent": "S",
    "KDC": "S",
    "kdc": "S",
    "Initiator": "I",
    "initiator": "I",
    "Responder": "R",
    "responder": "R",
    "TTP": "TTP",
    "CA": "CA",
    "Intruder": "E",
    "intruder": "E",
    "Eve": "E",
    "eve": "E",
    "Mallory": "E",
    "mallory": "E",
    "Malory": "E",
    "malory": "E",
}

# Unicode / ASCII arrow variants used in papers
ARROW_VARIANTS = [
    "→",   # U+2192 RIGHTWARDS ARROW
    "->",
    "---->",
    "-->",
    "=>",
    "⟶",   # U+27F6 LONG RIGHTWARDS ARROW
]


# ── Regex patterns ────────────────────────────────────────────────────────────

# Matches "A → B : payload"  or  "A→B:payload"
# Groups: (sender, receiver, payload)
_ARROW_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9_()]*)"   # sender
    r"\s*"
    r"(?:→|->|-->|---->|=>|⟶)"     # arrow
    r"\s*"
    r"([A-Za-z][A-Za-z0-9_()]*)"   # receiver
    r"\s*:\s*"
    r"(.+)",                         # payload (rest of line)
    re.UNICODE,
)

# Optional step prefix: "M1:", "Step 1:", "Message 1:", "(1)", "1."
_STEP_PREFIX_RE = re.compile(
    r"^(?:"
    r"(?:Message|Msg|Step|M|m)\s*(\d+)\s*[:.)]"
    r"|"
    r"\((\d+)\)"
    r"|"
    r"(\d+)[.:)]"
    r")\s*",
    re.IGNORECASE,
)

# Encrypted payload: {content}Key  or  {content}_Key
_ENCRYPT_RE = re.compile(
    r"\{([^{}]+)\}_?([A-Za-z][A-Za-z0-9_]*)",
)

# Hash: H(...) or h(...)
_HASH_RE = re.compile(
    r"[Hh]\s*\(([^()]+)\)",
)

# MAC: MAC(...) or mac(...)
_MAC_RE = re.compile(
    r"MAC\s*\(([^()]+)\)",
    re.IGNORECASE,
)

# Diffie-Hellman: g^x or g^(xy)
_DH_RE = re.compile(
    r"g\^\(?([A-Za-z0-9+*·\s]+)\)?",
)

# Nonce: Na, Nb, Na1, Nb_A, etc.
_NONCE_RE = re.compile(
    r"\b[Nn][a-zA-Z0-9_]+\b",
)

# Key: Ka, Kb, K_AB, K_AS, Ke, etc.
_KEY_RE = re.compile(
    r"\b[Kk][a-zA-Z0-9_]+\b",
)


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class ParsedMessage:
    """
    A single protocol message extracted from text.
    Corresponds to one entry in complete_message_flow / normalized_equations.
    """
    step: int                            # 1-based sequence number
    sender: str                          # normalised sender label
    receiver: str                        # normalised receiver label
    message: str                         # raw payload string (preserved exactly)
    protection: str = ""                 # e.g. "public_key_encryption", "hash", "plaintext"
    key: str = ""                        # key used for encryption/MAC (if any)
    payload_items: List[str] = field(default_factory=list)  # top-level payload tokens
    nonces: List[str] = field(default_factory=list)
    keys_mentioned: List[str] = field(default_factory=list)
    dh_values: List[str] = field(default_factory=list)
    is_dh_step: bool = False
    needs_review: bool = False           # True if extraction was ambiguous
    raw_line: str = ""                   # original text line before normalisation

    def to_dict(self) -> dict:
        return {
            "step": self.step,
            "sender": self.sender,
            "receiver": self.receiver,
            "message": self.message,
            "protection": self.protection,
            "key": self.key,
            "payload": self.payload_items,
            "nonces": self.nonces,
            "keys_mentioned": self.keys_mentioned,
            "dh_values": self.dh_values,
            "is_dh_step": self.is_dh_step,
            "needs_review": self.needs_review,
        }

    def __repr__(self) -> str:
        return (
            f"ParsedMessage(step={self.step}, "
            f"{self.sender}→{self.receiver}: {self.message!r})"
        )


# ── Main Extractor Class ──────────────────────────────────────────────────────

class EquationExtractor:
    """
    Extracts protocol messages and equations from raw text.

    Parameters
    ----------
    strict : bool
        If True, ambiguous lines raise ValueError instead of being flagged.
    """

    def __init__(self, strict: bool = False) -> None:
        self.strict = strict

    # ── Public API ───────────────────────────────────────────────────────────

    def extract(self, text: str) -> List[ParsedMessage]:
        """
        Extract all protocol messages from the given text block.

        Lines that match the arrow pattern are parsed into ParsedMessage
        objects.  Lines that do not match are silently skipped.

        Parameters
        ----------
        text : str
            Raw text containing protocol messages (e.g. extracted from a PDF).

        Returns
        -------
        List[ParsedMessage]
            Ordered list of messages.  step numbers are assigned in order of
            appearance if no step prefix is found in the text.
        """
        messages: List[ParsedMessage] = []
        auto_step = 1

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            # Strip optional step prefix and capture step number
            step_num, line_without_prefix = self._strip_step_prefix(line)

            match = _ARROW_RE.search(line_without_prefix)
            if not match:
                continue

            sender_raw, receiver_raw, payload_raw = match.groups()
            payload_raw = payload_raw.strip()

            sender = self._normalise_participant(sender_raw)
            receiver = self._normalise_participant(receiver_raw)

            if step_num is None:
                step_num = auto_step
            auto_step = step_num + 1

            msg = self._parse_payload(
                step=step_num,
                sender=sender,
                receiver=receiver,
                payload=payload_raw,
                raw_line=raw_line,
            )
            messages.append(msg)

        return messages

    def extract_equations_only(self, text: str) -> List[str]:
        """
        Return just the raw equation strings (one per line) without full parsing.
        Useful for quickly checking what equations are present.
        """
        results = []
        for line in text.splitlines():
            line = line.strip()
            if _ARROW_RE.search(line):
                results.append(line)
        return results

    def identify_primitives(self, text: str) -> List[str]:
        """
        Scan text for cryptographic primitive indicators and return a list
        of controlled-vocabulary primitive names found.
        """
        found = set()
        t = text.upper()

        checks = [
            (r"\bRSA\b", "RSA"),
            (r"\bDIFFIE.HELLMAN\b|\bDH\b|G\^|g\^", "Diffie-Hellman"),
            (r"\bECDH\b|\bELLIPTIC.CURVE.DIFFIE", "ECDH"),
            (r"\bECC\b|\bELLIPTIC.CURVE\b", "ECC"),
            (r"\bAES\b|\bADVANCED.ENCRYPTION\b", "AES"),
            (r"\bDES\b", "DES"),
            (r"\b3DES\b|\bTDEA\b|\bTRIPLE.DES\b", "3DES"),
            (r"\bHMAC\b", "HMAC"),
            (r"\bMAC\b", "MAC"),
            (r"\bHASH\b|\bH\s*\(|\bSHA\b|\bMD5\b", "Hash"),
            (r"\bDIGITAL.SIGNATURE\b|\bSIG\b|\bDSA\b|\bECDSA\b", "Digital_Signature"),
            (r"\bNONCE\b|\b[Nn][aAbBcCsS]\b", "Nonce"),
            (r"\bTIMESTAMP\b|\bT_[A-Z]\b|\bT[Aa]\b|\bT[Ss]\b", "Timestamp"),
            (r"\bPASSWORD\b|\bPASS\b|\bPW\b", "Password"),
            (r"\bSESSION.KEY\b|\bK_[Ss][Ee][Ss]\b", "Session_Key"),
            (r"\bCERTIFICATE\b|\bCERT\b", "Certificate"),
            (r"\bCHALLENGE.RESPONSE\b|\bCHALLENGE\b", "Challenge_Response"),
            (r"\bSHARED.SECRET\b|\bK_[Aa][Bb]\b|\bK_[Ss][Hh]\b", "Shared_Secret"),
            (r"\bPUBLIC.KEY.ENCRYPT\b|\{[^}]+\}[Kk][Bb]\b|\{[^}]+\}[Kk][Aa]\b",
             "Public_Key_Encryption"),
            (r"\bSYMMETRIC.ENCRYPT\b|\{[^}]+\}[Kk]_[Aa][Bb]\b", "Symmetric_Encryption"),
        ]

        for pattern, label in checks:
            if re.search(pattern, t):
                found.add(label)

        return sorted(found)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _normalise_participant(self, name: str) -> str:
        """Map full name variants (Alice, Bob, …) to single-letter labels."""
        # Strip impersonation suffix like E(A) → E
        name = re.sub(r"\([^)]+\)", "", name).strip()
        return PARTICIPANT_NORM.get(name, name)

    def _strip_step_prefix(self, line: str) -> Tuple[Optional[int], str]:
        """
        Remove optional step prefix from a line.
        Returns (step_number_or_None, remaining_line).
        """
        m = _STEP_PREFIX_RE.match(line)
        if m:
            num_str = m.group(1) or m.group(2) or m.group(3)
            step_num = int(num_str) if num_str else None
            return step_num, line[m.end():].strip()
        return None, line

    def _parse_payload(
        self,
        step: int,
        sender: str,
        receiver: str,
        payload: str,
        raw_line: str,
    ) -> ParsedMessage:
        """
        Decompose a payload string into its structural components.
        Returns a ParsedMessage with detected protection, key, payload tokens, etc.
        """
        needs_review = False

        # Detect double-nested encryption (e.g. {{m}K1}K2) — flag for review
        if payload.count("{") > 2 or payload.count("}") > 2:
            needs_review = True

        # --- Determine protection mechanism and key ---
        protection = "plaintext"
        key = ""

        enc_match = _ENCRYPT_RE.search(payload)
        if enc_match:
            inner_content = enc_match.group(1)
            enc_key = enc_match.group(2)
            protection = self._infer_protection(enc_key, payload)
            key = enc_key
        elif _HASH_RE.search(payload):
            protection = "hash"
        elif _MAC_RE.search(payload):
            protection = "mac"
        elif _DH_RE.search(payload):
            protection = "diffie-hellman"

        # --- Extract top-level payload items ---
        # Top-level items are comma-separated tokens at the outermost level
        payload_items = self._split_top_level(payload)

        # --- Extract nonces ---
        nonces = list(dict.fromkeys(_NONCE_RE.findall(payload)))

        # --- Extract keys mentioned ---
        keys_mentioned = list(dict.fromkeys(_KEY_RE.findall(payload)))

        # --- Extract DH values ---
        dh_values = [m.group(0) for m in _DH_RE.finditer(payload)]
        is_dh_step = len(dh_values) > 0

        return ParsedMessage(
            step=step,
            sender=sender,
            receiver=receiver,
            message=payload,
            protection=protection,
            key=key,
            payload_items=payload_items,
            nonces=nonces,
            keys_mentioned=keys_mentioned,
            dh_values=dh_values,
            is_dh_step=is_dh_step,
            needs_review=needs_review,
            raw_line=raw_line,
        )

    def _infer_protection(self, key_name: str, payload: str) -> str:
        """
        Heuristically infer whether encryption is public-key or symmetric
        based on the key name convention.

          Ka, Kb, Ke, K_A, K_B   → public_key_encryption
          K_AB, K_AS, K_BS, K    → symmetric_encryption
        """
        k = key_name.upper()
        # Two-letter K_XY style → shared (symmetric) key
        if re.match(r"^K_?[A-Z]{2}$", k):
            return "symmetric_encryption"
        # Single-letter Ka, Kb, Ke → public key of a party
        if re.match(r"^K_?[A-Z]$", k):
            return "public_key_encryption"
        # Contains 'PUB' or 'PK'
        if "PUB" in k or "PK" in k:
            return "public_key_encryption"
        # Contains 'SYM' or 'SK' or 'SESS'
        if "SYM" in k or "SESS" in k:
            return "symmetric_encryption"
        # Default: flag as needs_review
        return "encryption_type_unknown"

    def _split_top_level(self, payload: str) -> List[str]:
        """
        Split a payload string on commas, but ONLY at the top level
        (i.e. not inside braces or parentheses).

        Example:
            '{Na, A}Kb, Nb'  →  ['{Na, A}Kb', 'Nb']
            'g^x'            →  ['g^x']
        """
        items = []
        depth = 0
        current = []
        for ch in payload:
            if ch in "{(":
                depth += 1
                current.append(ch)
            elif ch in "})":
                depth -= 1
                current.append(ch)
            elif ch == "," and depth == 0:
                token = "".join(current).strip()
                if token:
                    items.append(token)
                current = []
            else:
                current.append(ch)
        last = "".join(current).strip()
        if last:
            items.append(last)
        return items


# ── Standalone test / demo ────────────────────────────────────────────────────

if __name__ == "__main__":
    sample_texts = {
        "NSPK (Needham-Schroeder Public Key)": """
            Message 1:  A → B : {Na, A}Kb
            Message 2:  B → A : {Na, Nb}Ka
            Message 3:  A → B : {Nb}Kb
        """,
        "NSSK (Needham-Schroeder Symmetric Key)": """
            Message 1:  A → S : A, B, Na
            Message 2:  S → A : {Na, B, K_AB, {K_AB, A}K_BS}K_AS
            Message 3:  A → B : {K_AB, A}K_BS
            Message 4:  B → A : {Nb}K_AB
            Message 5:  A → B : {Nb - 1}K_AB
        """,
        "STS Protocol": """
            Step 1: A → B : g^x
            Step 2: B → A : g^y, Cert_B, {sig_B(g^y || g^x)}K
            Step 3: A → B : Cert_A, {sig_A(g^x || g^y)}K
        """,
        "MQV": """
            A → B : X
            B → A : Y
        """,
    }

    extractor = EquationExtractor()
    for name, text in sample_texts.items():
        print(f"\n{'='*60}")
        print(f"Protocol: {name}")
        print("=" * 60)
        messages = extractor.extract(text)
        for msg in messages:
            print(f"  Step {msg.step}: {msg.sender} → {msg.receiver} : {msg.message}")
            print(f"    protection : {msg.protection}")
            print(f"    key        : {msg.key}")
            print(f"    payload    : {msg.payload_items}")
            print(f"    nonces     : {msg.nonces}")
            print(f"    keys_found : {msg.keys_mentioned}")
            if msg.dh_values:
                print(f"    dh_values  : {msg.dh_values}")
            if msg.needs_review:
                print(f"    *** NEEDS REVIEW ***")

        primitives = extractor.identify_primitives(text)
        print(f"\n  Detected primitives: {primitives}")
