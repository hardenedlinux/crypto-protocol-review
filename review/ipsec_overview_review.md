# Protocol Review: IPsec AH/ESP Overview (RFC 2410) v1.0

**Scope:** protocol logic only  
**Source:** RFC 2410 - The NULL Encryption Algorithm and Its Use With IPsec

## Summary
Findings: 2 Medium, 2 Low, 1 Info
Verdict: PASS-WITH-FIXES

## Goals, Threat Model, Invariants, Primitives, Proof Strategy
This review focuses on the NULL encryption algorithm specification and its implications for IPsec ESP security properties.

## Findings

### F-001 — NULL Encryption Provides Zero Confidentiality
- **Severity:** Medium
- **Pattern IDs:** C2, C6
- **Location:** Section 2; "NULL(b) = I(b) = b"
- **Description:** The NULL encryption algorithm is defined as the identity function - it transforms plaintext into identical ciphertext. The document explicitly states "The NULL encryption algorithm offers no confidentiality nor does it offer any other security service" (Section 4). The algorithm requires 0-bit keys and 0-bit IVs due to its stateless nature.
- **Attacker scenario:** An attacker monitoring traffic using ESP_NULL sees all plaintext traffic in the clear. If a deployer mistakenly believes ESP_NULL provides any security service (e.g., through confusion with "ESP with NULL encryption" vs "ESP with strong encryption"), they have deployed a protocol that offers no protection whatsoever.
- **Affected goals:** CONF (confidentiality), EA (encryption authentication)
- **References:** RFC 2410 Section 4
- **Fix:** The specification correctly identifies this as a documentation issue rather than a cryptographic flaw. Deployments must ensure ESP_NULL is only used when authentication without confidentiality is explicitly required, and that both endpoints understand no confidentiality is provided.

### F-002 — Authentication Mandatory Requirement Not Enforced by Protocol
- **Severity:** Medium
- **Pattern IDs:** A1, C2
- **Location:** Section 4; "it is imperative that an ESP SA specifies the use of at least one cryptographically strong encryption algorithm or one cryptographically strong authentication algorithm or one of each"
- **Description:** The RFC acknowledges that ESP allows configurations where neither encryption nor authentication is strong or present. While the document states the requirement for "at least one cryptographically strong" algorithm, the protocol definition itself permits NULL encryption without authentication, or weak algorithm selections. The phrase "or one of each" creates ambiguity about what constitutes acceptable minimal security.
- **Attacker scenario:** A misconfigured ESP deployment using NULL encryption (no confidentiality) combined with no or weak authentication provides an attacker with complete visibility into traffic and the ability to forge or modify packets if authentication is also NULL or weak.
- **Affected goals:** EA (encryption authentication), MA (message authentication), INT (integrity)
- **References:** RFC 2410 Section 4; RFC 2406 (ESP)
- **Fix:** The ESP specification should require authentication as mandatory when any encryption is employed, and should prohibit NULL encryption in production environments without explicit documentation of the security tradeoff.

### F-003 — ESP_NULL Does Not Authenticate IP Header (vs AH)
- **Severity:** Low
- **Pattern IDs:** A5
- **Location:** Section 1; "ESP_NULL does not include the IP header in calculating the authentication data"
- **Description:** Unlike AH which authenticates the immutable-in-transit portions of the IP header, ESP_NULL only authenticates the ESP payload. This creates a security differential: two packets with identical ESP payload but different IP header fields (e.g., source/destination) would appear valid to ESP_NULL but could be routed differently or be subject to IP-level attacks.
- **Attacker scenario:** An attacker capable of modifying IP header fields (which travel in plaintext with ESP) could potentially redirect or manipulate traffic without detection by ESP_NULL, since only the encrypted payload is authenticated.
- **Affected goals:** INT, MA
- **References:** RFC 2410 Section 1; RFC 2402 (AH)
- **Fix:** Document the security difference between AH and ESP_NULL clearly. Consider whether ESP_NULL should optionally support IP header authentication.

### F-004 — Combined Mode Security Boundary Ambiguity
- **Severity:** Low
- **Pattern IDs:** CP6, C2
- **Location:** Section 1; "further information on how the various pieces of ESP fit together"
- **Description:** The RFC references ESP combined mode (using both encryption and authentication) but does not specify how authentication data is computed over the ciphertext vs plaintext. This leaves ambiguity about whether authentication covers the IV/padding or only plaintext, which affects the security property against chosen-ciphertext attacks.
- **Attacker scenario:** Depending on implementation, a combined-mode ESP that authenticates plaintext instead of ciphertext (or vice versa) may be vulnerable to padding oracle or other modification attacks if the authentication is not properly applied.
- **Affected goals:** INT, EA
- **References:** RFC 2406 (ESP Combined Mode)
- **Fix:** ESP combined mode specifications should unambiguously define authentication coverage (Encrypt-then-MAC is recommended to prevent oracle attacks).

### F-005 — No IV Reuse Analysis for CBC Modes
- **Severity:** Info
- **Pattern IDs:** C1, C6
- **Location:** Section 2.2; cryptographic synchronization
- **Description:** The document notes NULL is stateless and does not require IV transmission. However, this is specific to NULL encryption. The RFC does not address IV handling for other ESP encryption algorithms (CBC mode), which is deferred to RFC 2406. IV reuse in CBC mode leads to confidentiality break (C1).
- **Attacker scenario:** N/A for NULL encryption
- **Affected goals:** N/A for NULL mode
- **References:** RFC 2406 for CBC IV requirements
- **Fix:** No fix needed for NULL; ensure RFC 2406 properly specifies IV handling requirements.

## Attack Pattern Checklist (SKILL.md §3)

### Authentication / Identity
| Pattern | Result | Notes |
|---------|--------|-------|
| A1 — Missing mutual authentication | N/A | ESP can use NULL auth; AH provides auth only |
| A2 — Unknown key-share | No | Key binding not discussed in NULL spec |
| A3 — Channel ID reuse | No | Per-SA identification |
| A4 — KCI | No | Long-term keys not involved |
| A5 — Identity misbinding | **Yes** | ESP_NULL doesn't auth IP header vs AH |
| A6 — Reflection attack | No | Stateless |
| A7 — Cross-protocol key reuse | No | NULL keys are 0-bits |
| A8 — Trust-on-first-use | No | IKE provides key exchange |
| A9 — LTK as session key | No | NULL requires no key |

### Replay / Ordering / Rollback
| Pattern | Result | Notes |
|---------|--------|-------|
| R1-R9 | N/A | Replay protection deferred to ESP/AH specs |

### Key Derivation
| Pattern | Result | Notes |
|---------|--------|-------|
| K1-K13 | N/A | NULL is identity function; no key derivation |

### Confidentiality / Encryption
| Pattern | Result | Notes |
|---------|--------|-------|
| C1 — Nonce reuse under same key | **Yes** | NULL is stateless (no nonce), but this creates false sense of security |
| C2 — CBC without MAC | **Yes** | Combined mode ambiguity (C2 applies to ESP overall, not just NULL) |
| C3 — Encrypt-then-MAC misimpl | **Yes** | Combined mode unspecified |
| C4 — ECB | No | Not applicable |
| C5 — CTR reuse | No | NULL not CTR |
| C6 — Stream cipher nonce reuse | N/A | NULL stateless, no nonce |
| C7-C16 | N/A | Not applicable to NULL |

### Forward / Future Secrecy
| Pattern | Result | Notes |
|---------|--------|-------|
| F1-F9 | N/A | NULL provides no keying material |

### Point Validation / EC
| Pattern | Result | Notes |
|---------|--------|-------|
| PV1-PV5 | N/A | Not applicable |

### Other Categories
- **Signatures (S1-S10):** N/A
- **Negotiation (N1-N7):** Deferred to IKE/ESP
- **Randomness (RD1-RD7):** N/A for NULL
- **Post-quantum (PQ1-PQ4):** N/A (1998 RFC)
- **Metadata (M1-M4):** **Yes** - All metadata visible with NULL encryption
- **Modern Frameworks:** N/A
- **PAKE:** N/A
- **Composition (CP2-CP6):** **Yes** - CP6 transcript ambiguity in combined mode

## Coverage Matrix
| Goal | Enforced | Confidence | Threat Model | Notes |
|------|----------|------------|--------------|-------|
| CONF | No | N/A | NULL provides none | Clear from spec |
| EA | Partial | Medium | MITM can see traffic | NULL |
| INT | Yes (if auth used) | High | Per-AH comparison | ESP_NULL only covers payload |
| MA | Yes (if auth used) | High | Same | Only with auth algorithm |
| FS | N/A | N/A | N/A | Not applicable to NULL |
