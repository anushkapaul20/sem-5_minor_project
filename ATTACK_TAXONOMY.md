# ATTACK TAXONOMY

**Project:** Cryptographic Protocol Attack Detection System  
**Version:** 0.1  
**Last Updated:** 2026-09-01

---

## Overview

This taxonomy defines the ten attack categories used for labeling the dataset and classifying ML model output. Each entry contains:

- **Definition** — what the attack is
- **Mechanism** — how it works
- **Conditions** — what protocol weaknesses it exploits
- **Attacker capabilities required**
- **Security property violated**
- **Canonical example protocol(s)**
- **Detection indicators**
- **Dataset label** (the exact string used in `attack_category`)

The taxonomy is a **controlled vocabulary**. No entry outside this list should appear as an `attack_category` value in the dataset.

---

## Attack Categories

---

### 1. MITM — Man-in-the-Middle

**Dataset label:** `MITM`

**Definition:**  
The attacker positions themselves between two communicating parties and relays (and potentially modifies) messages between them, such that each party believes they are communicating directly with the other.

**Mechanism:**  
- Attacker E intercepts messages between A and B.
- E can impersonate B to A, and A to B simultaneously.
- E establishes separate authenticated sessions with each party.
- Neither A nor B detects E's presence.

**Conditions that enable it:**  
- Protocol does not bind the communicating peer's identity to the key material.
- No mutual authentication of identity and session key simultaneously.
- Public keys are not verified against a trusted source.

**Attacker capabilities required:**  
`intercept`, `modify`, `forward`, `impersonate`

**Security property violated:**  
`authentication`, `mutual_authentication`, `key_establishment`

**Canonical example:**  
Needham-Schroeder Public Key Protocol (Lowe 1996) — attacker can fool A into thinking they share a session key with B, when actually A shares a key with E.

**Detection indicators:**  
- Peer identity is not cryptographically bound to the session key.
- Final message does not verify both parties know the same key.
- Message M2 can be forwarded by an attacker without decryption.

---

### 2. Replay — Replay Attack

**Dataset label:** `Replay`

**Definition:**  
The attacker captures a legitimate protocol message or an entire session and re-sends it at a later time, causing a party to accept stale or duplicate information.

**Mechanism:**  
- Attacker records a valid message `M = A → B : {data}`.
- Later, attacker re-sends the same `M` to B.
- B cannot distinguish the replayed message from a fresh one.
- B may re-establish a session, re-authenticate, or re-accept credentials.

**Conditions that enable it:**  
- Messages do not include freshness guarantees (nonces, timestamps, sequence numbers).
- No mechanism to detect duplicate messages.
- Session tokens have long or infinite validity.

**Attacker capabilities required:**  
`intercept`, `replay`

**Security property violated:**  
`key_freshness`, `authentication`, `entity_authentication`

**Canonical example:**  
Wide-Mouthed Frog protocol without nonce checking.

**Detection indicators:**  
- No nonce, timestamp, or sequence number in message.
- No challenge-response mechanism.
- B does not check whether it has seen this message before.

---

### 3. Reflection — Reflection Attack

**Dataset label:** `Reflection`

**Definition:**  
A special case of replay where the attacker sends a message back to the party who originally sent it, exploiting symmetric key usage or challenge-response structures to obtain an authenticated response without knowing the key.

**Mechanism:**  
- A sends a challenge encrypted with a shared key: `A → B : {Na}K_AB`
- Attacker opens a second session and sends A's own challenge back to A.
- A (acting as responder in the second session) decrypts and responds with `{Na}K_AB`.
- Attacker uses this response to complete the first session.

**Conditions that enable it:**  
- Same key used for both directions.
- No role differentiation in messages (initiator vs. responder messages look the same).
- Protocol allows parallel sessions.

**Attacker capabilities required:**  
`intercept`, `replay`, `reflect`

**Security property violated:**  
`authentication`, `mutual_authentication`

**Canonical example:**  
ISO/IEC 9798-2 two-pass authentication protocol variants.

**Detection indicators:**  
- Symmetric key used bidirectionally without role binding.
- Challenge message format is identical for initiator and responder.
- Parallel sessions not protected against cross-session attacks.

---

### 4. Impersonation — Impersonation Attack

**Dataset label:** `Impersonation`

**Definition:**  
The attacker convincingly pretends to be a legitimate party (A or B), causing the victim to believe they are communicating with that party when they are not.

**Mechanism:**  
- Attacker uses captured, replayed, or modified messages to present themselves as party A or B.
- The victim completes authentication, believing the other party is authenticated.
- The attacker may or may not need to know the impersonated party's secret key.

**Conditions that enable it:**  
- Weak authentication (not binding identity to cryptographic material).
- An attacker can forge or replay identity-bearing messages.
- No mutual authentication.

**Attacker capabilities required:**  
`intercept`, `forward`, `replay`, `impersonate`

**Security property violated:**  
`authentication`, `entity_authentication`, `mutual_authentication`

**Canonical example:**  
Protocols without entity authentication — attacker forwards a message from A to C while making C believe the message came directly from A.

**Detection indicators:**  
- Identity of sender is not cryptographically bound to message.
- Protocol does not verify liveness of the claimed identity.
- Attacker can construct a valid-looking message without the victim's key.

---

### 5. UKS — Unknown Key-Share

**Dataset label:** `UKS`

**Definition:**  
Two parties A and B complete a key agreement protocol and both believe they share a key. However, A believes they share the key with B, while B believes they share the key with a third party C (or vice versa). The key value itself is not revealed to an attacker, but the parties disagree on who they are communicating with.

**Mechanism:**  
- No direct forgery is needed.
- The attacker manipulates identity binding during the key agreement.
- Both parties compute the same key value, but have different beliefs about partner identity.

**Conditions that enable it:**  
- Key agreement protocol does not bind key material to identity certificates.
- No identity confirmation step after key derivation.
- Certificates or public keys can be substituted.

**Attacker capabilities required:**  
`intercept`, `modify` (identity fields only), `impersonate`

**Security property violated:**  
`key_establishment`, `authentication`, `mutual_authentication`

**Canonical example:**  
Diffie-Hellman key exchange without authentication — A and E complete DH, E and B complete DH, A believes they share a key with B.

**Detection indicators:**  
- Key material not cryptographically bound to peer identity.
- No identity confirmation in the final step.
- Identity is transmitted separately from key material and not included in any signed or MAC'd value.

---

### 6. Secrecy_Violation — Secrecy Violation

**Dataset label:** `Secrecy_Violation`

**Definition:**  
A secret value (session key, nonce, password, or other sensitive data) that should only be known to the intended parties becomes known to the attacker.

**Mechanism:**  
- Attacker intercepts, decrypts, or computes a value that should be secret.
- May result from weak encryption, improper key usage, or protocol logic flaws.
- The attacker obtains the session key and can decrypt past or future communications.

**Conditions that enable it:**  
- Session key derivation is predictable or based on publicly observable values.
- A secret is transmitted unencrypted or under a key the attacker knows.
- A party reveals a secret in a response message.

**Attacker capabilities required:**  
`intercept`, (optionally) `modify`, `compute`

**Security property violated:**  
`secrecy`, `confidentiality`

**Canonical example:**  
A protocol where a nonce or session key is encrypted with a public key but the attacker can substitute their own public key to decrypt it.

**Detection indicators:**  
- Secret appears in a message not protected by a key unknown to the attacker.
- Secret can be derived from publicly observable values.
- Encryption key used for the secret is known or obtainable by the attacker.

---

### 7. Authentication_Violation — Authentication Violation

**Dataset label:** `Authentication_Violation`

**Definition:**  
A party successfully completes authentication (believes they have authenticated the other party), but the authentication is not valid — the other party has not actually performed the steps that would prove their identity.

**Mechanism:**  
- Protocol claims authentication (e.g., non-injective agreement) but the verification conditions are not met.
- An attacker can cause a party to accept a forged or replayed authentication attempt.

**Conditions that enable it:**  
- Authentication does not require liveness (no nonce or timestamp).
- Protocol accepts previously-seen authentication messages.
- The authenticated identity is not bound to the session.

**Attacker capabilities required:**  
`intercept`, `replay` or `forward`

**Security property violated:**  
`authentication`, `entity_authentication`, `mutual_authentication`

**Canonical example:**  
A protocol where B considers A authenticated based on a message that A sent in a previous session.

**Detection indicators:**  
- No freshness guarantee in the authentication exchange.
- Authentication token could have been produced in a different session.
- Non-injective agreement claim fails in Scyther/ProVerif.

---

### 8. Session_Key_Compromise — Session-Key Compromise

**Dataset label:** `Session_Key_Compromise`

**Definition:**  
The session key established between two parties is revealed to or computable by the attacker, allowing them to decrypt all communications in that session.

**Mechanism:**  
- Different from general secrecy violation: specifically targets the session key.
- May occur through protocol flaws, key derivation weaknesses, or side-channel attacks.
- Attacker learns `K_session` and can decrypt `{M}K_session`.

**Conditions that enable it:**  
- Session key derived from public or predictable values.
- A party reveals the session key inadvertently.
- Key confirmation step is missing or bypassable.

**Attacker capabilities required:**  
`intercept`, `compute` (sometimes `compromise_key`)

**Security property violated:**  
`secrecy`, `key_establishment`, `confidentiality`

**Canonical example:**  
Static Diffie-Hellman without ephemeral keys — if the static private key is compromised, all session keys are compromised.

**Detection indicators:**  
- Session key not independently fresh per session.
- Session key derivable from values the attacker can observe.
- No key confirmation step.

---

### 9. KCI — Key-Compromise Impersonation

**Dataset label:** `KCI`

**Definition:**  
If party A's long-term private key is compromised, an attacker who knows A's private key can impersonate **other parties** to A (not just impersonate A to others). This is a property that should be resisted by well-designed protocols.

**Mechanism:**  
- Attacker learns A's long-term private key `sk_A`.
- Attacker initiates a session with A, impersonating B.
- Using `sk_A`, the attacker can compute what A expects to receive from B.
- A completes authentication, believing it communicated with B.

**Conditions that enable it:**  
- Protocol uses the same key for authentication and key derivation.
- Authentication of A's peer relies on A's own private key rather than B's key.
- No separate signing key for identity vs. DH contribution.

**Attacker capabilities required:**  
`impersonate`, `compromise_key` (A's key)

**Security property violated:**  
`authentication`, `key_establishment`, `entity_authentication`

**Canonical example:**  
Basic static DH: if A's private key `a` is compromised, an attacker can compute `g^(ax)` for any `x` they choose, allowing impersonation of B to A.

**Detection indicators:**  
- Authentication of B to A relies on values derived from A's own key.
- Protocol does not require explicit proof of B's private key.
- No separate key confirmation binding B's identity to B's private key independently.

---

### 10. Forward_Secrecy_Violation — Forward Secrecy Violation

**Dataset label:** `Forward_Secrecy_Violation`

**Definition:**  
Compromise of a long-term key at time T allows an attacker to decrypt **past** sessions (from time < T) that were recorded. A protocol with forward secrecy ensures that past session keys remain secret even after long-term key compromise.

**Mechanism:**  
- Attacker records encrypted sessions during the protocol's use.
- At a later time, attacker compromises A's (or B's) long-term private key.
- Attacker uses the compromised key to derive the session keys of past sessions.
- All recorded past communications are now decryptable.

**Conditions that enable it:**  
- Session key directly derived from long-term key material (not from ephemeral values).
- No ephemeral Diffie-Hellman component in key derivation.
- Session key `K = f(sk_A, pk_B)` rather than `K = f(g^a, g^b)` with fresh `a, b`.

**Attacker capabilities required:**  
`intercept` (record sessions), `compromise_key` (learn long-term key later)

**Security property violated:**  
`forward_secrecy`, `secrecy`

**Canonical example:**  
Static RSA key exchange (TLS-RSA without DHE): session key is encrypted with B's long-term public key; compromise of B's private key decrypts all past sessions. Ephemeral DH (DHE, ECDHE) provides forward secrecy.

**Detection indicators:**  
- Session key derivation does not use ephemeral (per-session) random values.
- Session key can be computed from long-term keys alone.
- No ephemeral DH exponent contributes to key derivation.

---

## Summary Table

| # | Label | Short Description | Key Weakness | Scyther Claim |
|---|-------|---------------------|--------------|---------------|
| 1 | `MITM` | Attacker relays between A and B | No peer binding in key | `Niagree`, `Alive` |
| 2 | `Replay` | Stale message accepted | No freshness (nonce/timestamp) | `Nisynch` |
| 3 | `Reflection` | Message sent back to originator | Same key both directions | `Nisynch` |
| 4 | `Impersonation` | Attacker pretends to be A or B | Weak identity binding | `Alive`, `Niagree` |
| 5 | `UKS` | Parties agree on key, disagree on partner | Identity not bound to key | `Niagree` |
| 6 | `Secrecy_Violation` | Secret value revealed to attacker | Improper encryption or derivation | `Secret` |
| 7 | `Authentication_Violation` | Authentication accepted but invalid | No liveness guarantee | `Nisynch`, `Alive` |
| 8 | `Session_Key_Compromise` | Session key known to attacker | Session key not independently fresh | `Secret` |
| 9 | `KCI` | Compromised key allows impersonation to its owner | Auth relies on victim's own key | `Alive`, `Niagree` |
| 10 | `Forward_Secrecy_Violation` | Past sessions broken after key compromise | No ephemeral key contribution | `Secret` |

---

## Multi-Label Rules

A protocol row may carry multiple attack labels. Valid combinations include:

| Combination | Rationale |
|-------------|-----------|
| `MITM` + `Impersonation` | MITM typically involves impersonation |
| `Replay` + `Authentication_Violation` | Replayed message breaks authentication |
| `Secrecy_Violation` + `Session_Key_Compromise` | Session key secrecy and specific session key |
| `KCI` + `Impersonation` | KCI is a form of impersonation |
| `Forward_Secrecy_Violation` + `Secrecy_Violation` | Both secrecy properties broken |

**Invalid / illogical combinations:**
- `None` with any other attack label — if `attack_present = 0`, `attack_category` must be `["None"]`
- `Reflection` + `Forward_Secrecy_Violation` — generally unrelated mechanisms

---

## Relationship to Security Properties

```
Secrecy ─────────────────→ Secrecy_Violation
                       ├──→ Session_Key_Compromise
                       └──→ Forward_Secrecy_Violation

Authentication ───────────→ Authentication_Violation
                       ├──→ Impersonation
                       ├──→ Reflection
                       ├──→ UKS
                       └──→ KCI

Key Establishment ────────→ MITM
                       ├──→ UKS
                       └──→ KCI

Freshness ────────────────→ Replay
                       └──→ Authentication_Violation
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.1 | 2026-09-01 | Initial taxonomy, 10 attack categories defined |
