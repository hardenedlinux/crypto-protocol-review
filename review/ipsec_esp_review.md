# Protocol Review: IPsec ESP (RFC 2406)

**Scope:** protocol logic only
**Source:** /home/john/crypto-protocol-review/flaw-examples/ipsec_esp.txt

## Summary
Findings: 1 Critical, 2 High, 1 Medium, 0 Low, 0 Info
Verdict: FAIL

## Goals, Threat Model, Invariants, Primitives, Proof Strategy
See respective artifacts. Goals: confidentiality (optional), data origin authentication (optional), integrity (optional), anti-replay (optional but requires authentication).

## Findings

### F-001 — Encryption-Only Mode Permits Bit-Flipping Attacks
- **Severity:** Critical
- **Pattern IDs:** C2, A1
- **Location:** Section 2.7 (Authentication Data), Section 3.3.2 (Packet Encryption), Section 5 (Conformance Requirements)
- **Description:** RFC 2406 permits ESP to be configured with encryption-only (NULL authentication). The mandatory-to-implement encryption algorithm is DES-CBC (RFC 2405). When authentication is disabled, there is no integrity protection whatsoever on the ciphertext. An attacker can flip bits in the CBC ciphertext, which produces predictable changes in decrypted plaintext, enabling practical bit-flipping attacks against confidentiality-only SAs.
- **Attacker scenario:** A man-in-the-middle intercepts an ESP packet sent with confidentiality-only (authentication=NULL). By XORing a selected bit into a ciphertext block at offset p, the attacker causes the corresponding bit in the decrypted plaintext of that block to flip. By carefully positioning the flip (e.g., in the Payload Data or Next Header field), the attacker can manipulate the decrypted content without detection. The receiver processes the modified packet as valid since no ICV check occurs.
- **Affected goals:** IND (indistinguishability), KS (key secrecy), EA (encryption/authentication binding)
- **References:** Bellovin 1996 ("Problem Areas for the IP Security Protocols"); Vaudenay 2002 (padding oracle class); CRYPTO 2000 (CBC bit-flipping)
- **Fix:** Mandate authentication whenever encryption is used. If ESP is used without AH, require the authentication service. Alternatively, use AES-GCM or AES-CCM which provide authenticated encryption.

### F-002 — CBC Mode Without Authentication Allows Cut-and-Paste Attacks
- **Severity:** High
- **Pattern IDs:** C2
- **Location:** Section 3.3.2; Section 5 (mandates DES-CBC)
- **Description:** The spec mandates DES-CBC as the default encryption algorithm. CBC mode is inherently malleable without an accompanying MAC. An attacker can collect ciphertext blocks from one SA and paste them into another SA's packets (or same SA if the IV is predictable), or reorder ciphertext blocks, causing predictable plaintext modifications upon decryption. The default padding scheme (Section 2.4) offers only limited protection if receivers check padding values, but this is not mandatory.
- **Attacker scenario:** Attacker captures ciphertext blocks from multiple packets. By rearranging or combining blocks from different packets, the attacker creates new valid ciphertext that decrypts to chosen plaintext patterns. This enables modification of payload data, Next Header values, or padding length without detection.
- **Affected goals:** INT (integrity), IND
- **References:** RFC 2405 (DES-CBC with explicit IV); Bellovin 1996
- **Fix:** Use AES-GCM, AES-CCM, or ChaCha20-Poly1305 which provide authenticated encryption. If CBC must be used, apply HMAC after encryption (Encrypt-then-MAC) with a domain-separated key.

### F-003 — No Ephemeral Key Contribution When Using Static Keys
- **Severity:** High
- **Pattern IDs:** F1
- **Location:** Section 3.3.1 (Security Association Lookup); Section 5 (Conformance Requirements); IKE RFC 2409 (referenced in Section 1)
- **Description:** RFC 2406 supports manual key management and IKE (RFC 2409) which may establish SAs without Diffie-Hellman key agreement. When static pre-shared keys or RSA-based IKE authentication is used without DH, the session encryption key has no ephemeral contribution. Compromise of the static key compromises all past and future sessions (no forward secrecy).
- **Attacker scenario:** If an attacker records encrypted traffic and later obtains the static long-term key (via cryptanalysis, key extraction, or coercion), they can decrypt all previously recorded traffic and all future traffic until the key is rotated. This is especially problematic for long-lived SAs.
- **Affected goals:** FS (forward secrecy), PCS (post-compromise security)
- **References:** RFC 2409 (IKE); RFC 2401 (IPsec Architecture)
- **Fix:** Mandate DH or ECDH key agreement for all automated key management. Deprecate static key-only configurations for ESP. If PFS is required, use DH with appropriate group size.

### F-004 — Encrypt-then-MAC but Authentication Protects Ciphertext Not Plaintext
- **Severity:** Medium
- **Pattern IDs:** C3
- **Location:** Section 3.3.2 (lines 604-614), Section 3.3.4 (ICV calculation), Section 3.4.4 (ICV verification)
- **Description:** The spec correctly specifies encrypt-then-authenticate: "encryption is performed first, before the authentication" (Section 3.3.2 line 604). However, the ICV is computed over the ESP packet minus the Authentication Data field (Section 3.3.4 lines 651-656), which means it covers the ciphertext, not the plaintext. This creates a mismatch: decryption is required before ICV verification can confirm plaintext integrity. If authentication fails, the receiver has already performed a wasted decryption. More critically, when authentication is NULL, there is no integrity on either ciphertext or plaintext.
- **Attacker scenario:** If an implementation attempts to optimize by deferring decryption until after ICV verification (parallel processing per Section 3.4.4), a timing or cache side channel could leak plaintext from corrupted ciphertext. Additionally, the design does not prevent chosen ciphertext attacks where modification of ciphertext is not detected until after decryption.
- **Affected goals:** INT, EA
- **References:** RFC 2406 Section 3.3.2, 3.3.4
- **Fix:** For CBC-based modes without a separate MAC, this design is inherently flawed. Switch to AEAD modes (AES-GCM, ChaCha20-Poly1305) where authentication and encryption are integrated. If separate authentication is required, apply MAC to plaintext (MAC-then-encrypt) with proper domain separation.

## Coverage Matrix

| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| KS (Key Secrecy) | Partial | High | Static keys allowed, no FS | F-003 |
| IND (Indistinguishability) | No | High | Encryption-only mode enables attacks | F-001 |
| INT (Integrity) | No | High | Authentication optional; encryption-only has no INT | F-001, F-002 |
| EA (Encryption/Auth binding) | No | High | Encryption without auth allowed | F-001 |
| MA (Mutual Authentication) | Optional | Medium | Per-SA; not mandated with encryption | F-001 |
| FS (Forward Secrecy) | No | High | Static keys with no DH contribution | F-003 |
| PCS (Post-Compromise) | No | Medium | No ratchet or healing mechanism in ESP | F-3 |
| REPLAY (Anti-replay) | Optional | Medium | Requires authentication; disabled by sender | R7 |

## Attack Pattern Checklist

| Pattern ID | Description | Result |
|------------|-------------|--------|
| A1 | Missing mutual authentication | YES - Encryption-only SA has no authentication |
| A2 | Unknown key-share | No |
| A3 | Channel ID reuse | No |
| A4 | KCI | No (auth optional) |
| A5 | Identity misbinding | No |
| A6 | Reflection attack | No |
| A7 | Cross-protocol key reuse | No |
| A8 | TOFU without downgrade | No |
| A9 | LTK used directly | YES - Static keys used as session keys |
| R1 | Replay of Finished | N/A |
| R2 | Replay of key-exchange | No (anti-replay optional) |
| R3-R5 | Downgrade attacks | No |
| R6 | Rollback | No |
| R7 | 0-RTT replay | N/A (no 0-RTT in ESP) |
| R8 | Resumption without binding | No (no resumption in ESP) |
| R9 | Stale message replay | Possible with anti-replay disabled |
| K1 | KDF without domain separation | Unknown (depends on algorithm spec) |
| K2 | KDF without transcript | Unknown |
| K6 | Bidirectional keys no per-direction | No (per-direction keys via SA) |
| K10 | Non-contributory KEX | YES - Static keys with IKE (no DH) |
| K11 | Missing key confirmation | YES - No key confirmation in ESP |
| C1 | Nonce reuse | Possible if counter overflows |
| C2 | CBC without MAC | YES - DES-CBC without mandatory MAC |
| C3 | Encrypt-then-MAC misimplemented | PARTIAL - Correct order but MAC-on-ciphertext |
| C4 | ECB for structured data | No |
| C5 | CTR with reused counter | Possible (IV reuse in CBC) |
| C6 | Stream cipher nonce reuse | No (CBC mode) |
| C10 | Same key both directions | Per-SA, unidirectional |
| F1 | No ephemeral contribution | YES - Static keys without DH |
| F2 | Static DH claimed FS | N/A |
| F5 | LTK directly encrypts traffic | YES - Static keys for ESP encryption |
| F8 | Resumption reuses old keys | No resumption |
| PV1-PV5 | EC point validation | N/A (no DH in ESP spec) |
