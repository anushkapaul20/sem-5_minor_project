# DATA DICTIONARY

**Project:** Cryptographic Protocol Attack Detection System  
**Version:** 0.1  
**Last Updated:** 2026-09-01  
**Applies To:** `dataset_v0.csv`, `dataset_v0.json`, and all subsequent versions

---

## Overview

Each row in the dataset represents **one protocol instance from one paper**.  
If a paper presents both the original (secure) protocol and an attacked variant, they are stored as **separate rows** with the same `paper_id`.

---

## Field Reference

### ── Paper / Source Metadata ──────────────────────────────────────────

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `paper_id` | string | ✅ Yes | Unique identifier assigned to the source paper. Format: `paper_NNN` | `paper_001` |
| `paper_title` | string | ✅ Yes | Full title of the source paper, exactly as printed | `"Lowe's Analysis of the Needham-Schroeder Protocol"` |
| `authors` | string | ✅ Yes | Comma-separated list of author names, as printed in the paper | `"Lowe, G."` |
| `publication_year` | integer | ✅ Yes | Year the paper was published | `1996` |
| `source_link` | string | ⬜ Recommended | DOI or URL of the paper. Use `UNAVAILABLE` if not found | `"https://doi.org/10.1016/..."` |
| `source_type` | string | ✅ Yes | Type of source. Controlled vocabulary. | `conference_paper` |
| `source_page` | string | ✅ Yes | Page range within the paper where the protocol is described | `"pp. 3-4"` |
| `equation_source_page` | string | ⬜ Recommended | Specific page(s) where the equations were found | `"p. 3"` |
| `attack_source_page` | string | ⬜ Recommended | Specific page(s) where the attack is described | `"p. 5"` |

**Controlled vocabulary for `source_type`:**
- `conference_paper`
- `journal_article`
- `thesis`
- `technical_report`
- `textbook`
- `rfc`
- `standard`

---

### ── Protocol Identity ─────────────────────────────────────────────

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `protocol_name` | string | ✅ Yes | Name of the protocol as given in the paper | `"Needham-Schroeder Public Key Protocol"` |
| `protocol_type` | string | ✅ Yes | Category of the protocol | `"authentication"` |
| `protocol_variant` | string | ⬜ Optional | If this is a modified/attacked variant, name it here | `"Lowe fix"`, `"attacked version"` |

**Controlled vocabulary for `protocol_type`:**
- `authentication`
- `key_exchange`
- `key_agreement`
- `authenticated_key_exchange`
- `password_authentication`
- `group_key_agreement`
- `session_establishment`

---

### ── Protocol Participants ─────────────────────────────────────────

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `participants` | JSON array | ✅ Yes | List of all participants (roles) in the protocol | `["A", "B", "S"]` |
| `participant_count` | integer | ✅ Yes | Number of participants | `2` |
| `trusted_third_party` | boolean | ⬜ Optional | Whether a TTP/CA/KDC is involved | `false` |

---

### ── Cryptographic Primitives ──────────────────────────────────────

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `cryptographic_primitives` | JSON array | ✅ Yes | List of cryptographic operations/algorithms used. From controlled vocabulary. | `["Public_Key_Encryption", "Nonce"]` |
| `cryptographic_parameters` | string | ⬜ Optional | Key sizes, group parameters, or specific algorithmic parameters mentioned | `"RSA-2048, 128-bit nonces"` |

**Controlled vocabulary for `cryptographic_primitives`:**
- `RSA`
- `Diffie-Hellman`
- `ECDH`
- `ECC`
- `AES`
- `DES`
- `3DES`
- `Hash`
- `HMAC`
- `MAC`
- `Digital_Signature`
- `Public_Key_Encryption`
- `Symmetric_Encryption`
- `Nonce`
- `Timestamp`
- `Password`
- `Shared_Secret`
- `Session_Key`
- `Certificate`
- `Challenge_Response`

---

### ── Protocol Equations ────────────────────────────────────────────

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `original_equations` | string (multiline) | ✅ Yes | Exact equations as written in the paper. Never modified. | `"A → B : {Na,A}Kb\nB → A : {Na,Nb}Ka\nA → B : {Nb}Kb"` |
| `normalized_equations` | JSON array | ✅ Yes | Machine-readable decomposition of each equation step. See format below. | *(see below)* |

**`normalized_equations` format (JSON array of objects):**

```json
[
  {
    "step": 1,
    "sender": "A",
    "receiver": "B",
    "message": "{Na,A}Kb",
    "protection": "public_key_encryption",
    "key": "Kb",
    "payload": ["Na", "A"]
  },
  {
    "step": 2,
    "sender": "B",
    "receiver": "A",
    "message": "{Na,Nb}Ka",
    "protection": "public_key_encryption",
    "key": "Ka",
    "payload": ["Na", "Nb"]
  }
]
```

**Rule:** `original_equations` is **read-only after extraction**. Never modify it.  
**Rule:** If equations cannot be verified from the paper, set `equation_status = NOT_FOUND`.

---

### ── Message Flow ──────────────────────────────────────────────────

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `message_1` | string | ⬜ Optional | Human-readable form of step 1 | `"A → B : {Na,A}Kb"` |
| `message_2` | string | ⬜ Optional | Human-readable form of step 2 | `"B → A : {Na,Nb}Ka"` |
| `message_3` | string | ⬜ Optional | Human-readable form of step 3 | `"A → B : {Nb}Kb"` |
| `message_4` | string | ⬜ Optional | Human-readable form of step 4 | |
| `message_5` | string | ⬜ Optional | Human-readable form of step 5 | |
| `complete_message_flow` | JSON array | ✅ Yes | **Full** machine-readable message sequence (no step limit). Same format as `normalized_equations`. | *(see above)* |
| `message_step_count` | integer | ✅ Yes | Total number of protocol steps | `3` |

**Note:** `message_1` through `message_5` are convenience fields for quick access.  
`complete_message_flow` is the authoritative field and supports any number of steps.

---

### ── Attacker Model ────────────────────────────────────────────────

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `attacker_model` | string | ✅ Yes | Name of the attacker model used | `"Dolev-Yao"` |
| `attacker_identity` | string | ⬜ Optional | Who the attacker is (e.g., outsider, insider, compromised party) | `"outsider"` |
| `attacker_capabilities` | JSON array | ✅ Yes | What the attacker can do. From controlled vocabulary. | `["intercept", "modify", "replay", "forward"]` |

**Controlled vocabulary for `attacker_capabilities`:**
- `intercept` — read messages in transit
- `modify` — alter messages in transit
- `replay` — re-send previously captured messages
- `forward` — forward messages without modification
- `reflect` — send a message back to its original sender
- `impersonate` — pretend to be a legitimate party
- `block` — prevent delivery of a message
- `compute` — perform arbitrary computations
- `compromise_key` — learn a party's long-term key

---

### ── Attack Information ────────────────────────────────────────────

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `attack_name` | string | ✅ Yes | Name of the attack as given in the paper. Use `None` if no attack. | `"Lowe's MITM Attack"` |
| `attack_category` | JSON array | ✅ Yes | One or more categories from controlled vocabulary | `["MITM", "Impersonation"]` |
| `attack_present` | integer | ✅ Yes | **Binary label.** `1` = attack found, `0` = no attack (secure) | `1` |
| `protocol_secure` | boolean | ✅ Yes | Whether the protocol is considered secure | `false` |
| `attacker_action` | JSON array | ⬜ Recommended | List of attacker actions performed in the attack | `["intercept", "impersonate", "forward"]` |

**Controlled vocabulary for `attack_category`:**
- `MITM`
- `Replay`
- `Reflection`
- `Impersonation`
- `UKS`
- `Secrecy_Violation`
- `Authentication_Violation`
- `Session_Key_Compromise`
- `KCI`
- `Forward_Secrecy_Violation`
- `None` — when `attack_present = 0`

---

### ── Attack Trace ──────────────────────────────────────────────────

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `attack_trace` | string (multiline) | ⬜ Recommended | Step-by-step description of how the attack proceeds, from the paper | *(see format below)* |
| `attack_trace_structured` | JSON array | ⬜ Optional | Machine-readable version of the attack trace | *(see format below)* |

**`attack_trace` (human-readable text format):**

```
Step 1: A → E(B) : {Na, A}Kb
        (A initiates with E, thinking E is B)
Step 2: E(A) → B : {Na, A}Kb
        (E forwards message to B, pretending to be A)
Step 3: B → E(A) : {Na, Nb}Ka
        (B responds to A, E intercepts)
Step 4: E(B) → A : {Na, Nb}Ka
        (E forwards to A)
Step 5: A → E(B) : {Nb}Kb
        (A completes, E intercepts Nb)
Step 6: E(A) → B : {Nb}Kb
        (E completes the session with B, impersonating A)
```

**`attack_trace_structured` (JSON format):**

```json
[
  {
    "step": 1,
    "sender": "A",
    "receiver": "E",
    "intended_receiver": "B",
    "message": "{Na,A}Kb",
    "attacker_role": "receive"
  },
  {
    "step": 2,
    "sender": "E",
    "receiver": "B",
    "impersonating": "A",
    "message": "{Na,A}Kb",
    "attacker_role": "forward"
  }
]
```

**Rule:** The attack trace must come from the paper or from Scyther output. Never invented.

---

### ── Security Properties ───────────────────────────────────────────

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `security_property_targeted` | JSON array | ✅ Yes | Which security property the attack violates | `["authentication", "secrecy"]` |
| `security_violation` | string | ⬜ Recommended | Plain-language description of what is broken | `"B believes it is communicating with A, but is actually communicating with E"` |

**Controlled vocabulary for `security_property_targeted`:**
- `secrecy`
- `authentication`
- `forward_secrecy`
- `key_freshness`
- `mutual_authentication`
- `non_repudiation`
- `key_confirmation`
- `anonymity`
- `entity_authentication`
- `key_establishment`

---

### ── Scyther Integration ───────────────────────────────────────────

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `scyther_model_available` | boolean | ✅ Yes | Whether a `.spdl` Scyther model has been generated | `false` |
| `scyther_model_path` | string | ⬜ Optional | Path to the `.spdl` file | `"scyther/models/needham_schroeder.spdl"` |
| `scyther_verification_result` | string | ⬜ Optional | Raw result from Scyther. Use `NOT_RUN` if Scyther not available. | `"ATTACK_FOUND"` |
| `scyther_attack_trace` | string | ⬜ Optional | Attack trace output from Scyther. Only populated from actual Scyther output. | |

**Allowed values for `scyther_verification_result`:**
- `VERIFIED_SECURE`
- `ATTACK_FOUND`
- `NOT_RUN` — Scyther not installed or not yet run
- `TIMEOUT`
- `PARSE_ERROR`
- `REQUIRES_REVIEW`

---

### ── Extraction Metadata ───────────────────────────────────────────

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `extraction_status` | string | ✅ Yes | How this record was created. Controlled vocabulary. | `AUTO_EXTRACTED` |
| `equation_status` | string | ✅ Yes | Status of equation extraction | `HUMAN_VERIFIED` |
| `attack_status` | string | ✅ Yes | Status of attack extraction | `REQUIRES_REVIEW` |
| `extraction_date` | string (ISO 8601) | ✅ Yes | Date this row was created | `"2026-09-01"` |
| `last_verified_date` | string (ISO 8601) | ⬜ Optional | Date of last human verification | `"2026-09-15"` |
| `verified_by` | string | ⬜ Optional | Initials or name of the person who verified | `"AP"` |
| `notes` | string | ⬜ Optional | Free-text notes for manual review | `"Equation on p.3 uses non-standard notation"` |

**Controlled vocabulary for `extraction_status`:**
- `AUTO_EXTRACTED` — generated by the pipeline, not yet human-checked
- `HUMAN_VERIFIED` — manually reviewed and confirmed correct
- `REQUIRES_REVIEW` — flagged for human attention

**Controlled vocabulary for `equation_status` and `attack_status`:**
- `FOUND` — located in the paper
- `NOT_FOUND` — paper exists but field not found
- `HUMAN_VERIFIED`
- `REQUIRES_REVIEW`
- `UNAVAILABLE` — paper itself could not be accessed

---

## Full Field List (Quick Reference)

```
paper_id
paper_title
authors
publication_year
source_link
source_type
source_page
equation_source_page
attack_source_page
protocol_name
protocol_type
protocol_variant
participants
participant_count
trusted_third_party
cryptographic_primitives
cryptographic_parameters
original_equations
normalized_equations
message_1
message_2
message_3
message_4
message_5
complete_message_flow
message_step_count
attacker_model
attacker_identity
attacker_capabilities
attack_name
attack_category
attack_present             ← PRIMARY BINARY LABEL
protocol_secure
attacker_action
attack_trace
attack_trace_structured
security_property_targeted
security_violation
scyther_model_available
scyther_model_path
scyther_verification_result
scyther_attack_trace
extraction_status          ← EXTRACTION QUALITY FLAG
equation_status
attack_status
extraction_date
last_verified_date
verified_by
notes
```

Total fields: **48**

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.1 | 2026-09-01 | Initial data dictionary, 48 fields defined |
