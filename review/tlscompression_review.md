# Protocol Review: TLS Compression Methods v1.0 (RFC 3749)

**Scope:** protocol logic only
**Source:** flaw-examples/tls1compression.txt

## Summary
Findings: 1 Critical, 0 High, 0 Medium, 0 Low, 0 Info
Verdict: FAIL

## Goals, Threat Model, Invariants, Primitives, Proof Strategy
See goals.md, threat-model.md, invariants.md, primitives.md, proof-sketch.md.

## Findings

### F-001 — Plaintext Compression Before Encryption (CRIME/BREACH)
- **Severity:** Critical
- **Pattern IDs:** C8
- **Location:** RFC 3749 §2, §6 (Security Considerations); TLS Record Protocol compression ordering
- **Description:** RFC 3749 specifies DEFLATE compression applied to plaintext data **before** encryption in the TLS Record Protocol. The compression ratio varies based on plaintext content, causing compressed payload lengths to leak information about the original uncompressed data. This enables the CRIME (2012) and BREACH (2013) attacks, where an active network attacker can recover secrets (e.g., HTTP cookies, authentication tokens) by observing compressed payload lengths across multiple requests.
- **Attacker scenario:** An active MITM observes encrypted TLS records containing compressed HTTP requests. By injecting a partial guess (e.g., a cookie prefix) into requests and observing whether the compressed length decreases, the attacker can iteratively recover secret values byte-by-byte. The compression algorithm (DEFLATE) achieves better ratios when the guess matches the next bytes of the secret, making the compressed length a visible oracle.
- **Affected goals:** IND (ciphertext indistinguishability), EA (encryption authenticity is unaffected but confidentiality is broken)
- **References:** 
  - CRIME attack (2012): https://www.iacr.org/crypto/2012/317
  - BREACH attack (2013): https://www.breachattack.com/
  - RFC 3749 §6 acknowledges length leakage but understates severity
- **Fix:** Disable TLS-level compression (mandatory in TLS 1.3). For HTTP, use TLS 1.3 or implement CSRF tokens with random masking. Response compression should not be used when secrets are transmitted. TLS 1.3 (RFC 8446) removed compression entirely to address this class of attack.

## Coverage Matrix
| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| IND  | No       | N/A        | N/A          | C8 breaks IND under active attack |
| EA   | Yes      | High       | MITM         | Authentication unaffected |
| KS   | Yes      | High       | Passive      | Key secrecy unaffected |

---

## Attack Pattern Catalog Check (§3)

### Confidentiality / encryption
| ID | Pattern | Result | Notes |
|----|---------|--------|-------|
| C1 | Nonce reuse under same key | N/A | Not applicable to compression spec |
| C2 | CBC without MAC | N/A | Not applicable to compression spec |
| C3 | Encrypt-then-MAC misimplementation | N/A | Not applicable to compression spec |
| C4 | ECB for structured data | N/A | Not applicable to compression spec |
| C5 | CTR with reused counter | N/A | Not applicable to compression spec |
| C6 | Stream cipher with reused nonce | N/A | Not applicable to compression spec |
| C7 | KEM decapsulation failure distinguishable | N/A | Not applicable to compression spec |
| **C8** | **Plaintext compression before encryption** | **YES** | **DEFLATE applied before encryption; RFC 3749 §6 acknowledges length leakage but does not mandate disabling compression** |
| C9 | Length leakage via padding | N/A | Not the primary flaw |
| C10 | Same key used for both directions | N/A | Not applicable to compression spec |
| C11 | Nonce not guaranteed unique | N/A | Not applicable to compression spec |
| C12 | Online decryption partitioning oracle | N/A | Not applicable to compression spec |
| C13 | SM4 modes IV reuse | N/A | Not applicable to compression spec |
| C14 | AEAD lacks key commitment | N/A | Not applicable to compression spec |
| C15 | RSA-PKCS#1 v1.5 encryption oracle | N/A | Not applicable to compression spec |
| C16 | AEAD tag truncation | N/A | Not applicable to compression spec |

**C8 Result: YES** — This is the core protocol-level flaw. RFC 3749 standardizes DEFLATE compression applied to plaintext before encryption, enabling CRIME/BREACH.
