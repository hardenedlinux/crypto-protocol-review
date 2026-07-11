# Protocol Review: Diffie-Hellman Key Agreement Method (RFC 2631)

**Scope:** protocol logic only  
**Source:** `flaw-examples/dh_key_agreement.txt` (RFC 2631)

---

## ⚠️ Important Limitations

**This report is a reference, not a replacement for expert review.**

- AI-generated protocol analysis can miss critical vulnerabilities
- Cryptography engineering requires peer-reviewed expertise
- Formal verification (ProVerif, Tamarin) and implementation audit are required
- Side channels, constant-time code, and RNG internals are out of scope

**For production systems, engage certified cryptography engineers and conduct formal verification before deployment.**

*As JP Aumasson noted in [Murphy's Laws of Cryptography](https://www.aumasson.jp/murphy.html): "Any large enough system will include broken cryptography" and "New cryptography generates new attacks." Cryptographic protocol design is exceptionally difficult — failures are subtle, consequences are catastrophic, and automated analysis cannot catch all flaws.*

---

## Summary

Findings: 2 Critical, 2 High, 2 Medium, 0 Low, 0 Info  
Verdict: **FAIL**

RFC 2631 standardizes ANSI X9.42-style DH with optional public-key validation, SHA-1 KDF, static-static mode without FS, and weak historical parameter floors (q ≥ 160).

## Goals, Threat Model, Invariants, Primitives, Proof Strategy

| Artifact | Summary |
|----------|---------|
| Goals | Shared secret ZZ → keying material for symmetric KEKs; recipient certified |
| Modes | Ephemeral-Static (MUST); Static-Static (MAY) |
| Threat model | Active MITM on public keys; small-subgroup; LT key compromise |
| Primitives | FF-DH; SHA-1 KDF; 3DES KEK examples |
| Proof | Informal; cites [LAW98][LL97] |

## Findings

### F-001 — Public-key validation optional (small-subgroup / non-contributory)
- **Severity:** Critical
- **Pattern IDs:** K10, PV2, PV4
- **Location:** §2.1.5 (MAY validate); §2.3 SHOULD validate ephemeral; §2.4 SHOULD validate or trust CA; Security Considerations
- **Description:** Validation of y (range + y^q ≡ 1 mod p) is not MUST. Accepting small-order y forces ZZ into a tiny subgroup → attacker recovers ZZ.
- **Attacker scenario:** MITM substitutes small-order public key; peer computes weak ZZ; attacker brute-forces subgroup and derives KM.
- **Affected goals:** KS, KA, IND
- **References:** RFC 2631 §2.1.5, §2.3–2.4; Lim-Lee [LL97]
- **Fix:** MUST validate peer public keys (or use safe primes / approved groups with mandatory checks per SP 800-56A).

### F-002 — Static-static mode: no FS under LT compromise
- **Severity:** Critical
- **Pattern IDs:** F1, F2, A4
- **Location:** §2.4 Static-Static Mode
- **Description:** Both parties use long-term DH keys; ZZ repeats modulo partyAInfo. No ephemeral contribution → compromise of either LT private key exposes past ZZ (and enables KCI-class issues for static-static DH AKEs).
- **Attacker scenario:** Steal static DH private key → recompute historical ZZ for captured transcripts (partyAInfo often known).
- **Affected goals:** FS, KS, KCI
- **References:** RFC 2631 §2.4; SKILL.md F1/A4
- **Fix:** Prefer Ephemeral-Static or ephemeral-ephemeral; rotate static keys; treat static-static as non-FS.

### F-003 — SHA-1 used as KDF hash
- **Severity:** High
- **Pattern IDs:** K3, N7
- **Location:** §2.1.2 KM = H(ZZ ‖ OtherInfo) with H = SHA-1
- **Description:** Single SHA-1 invocations (counter-style) derive keying material. SHA-1 disallowed for new KDF/PRF per §2.8; non-uniform ZZ should use a modern Extract (HKDF).
- **Attacker scenario:** Weakens long-term security margin; compliance failure.
- **Affected goals:** KS
- **References:** FIPS 180; NIST SP 800-56C / RFC 5869
- **Fix:** HKDF-SHA-256+ or SP 800-56C with SHA-256+.

### F-004 — Parameter size floor (q ≥ 160) below modern 128-bit target
- **Severity:** High
- **Pattern IDs:** N7
- **Location:** §2.2 (m ≥ 160 ⇒ q ≥ 160)
- **Description:** 160-bit subgroup ≈80-bit classical security — below silent 128-bit default (need ≥256-bit ECC or FF ≥3072 / large q).
- **Attacker scenario:** NFS/index-calculus against undersized groups (Logjam-class if weak/shared primes).
- **Affected goals:** KS, classical-param-strength
- **References:** NIST SP 800-57; RFC 7919
- **Fix:** Named groups ffdhe3072+ or ECDH X25519/P-256+.

### F-005 — partyAInfo freshness only loosely constrained
- **Severity:** Medium
- **Pattern IDs:** R2, FR
- **Location:** §2.1.2–2.1.3; §2.3–2.4
- **Description:** Static-static requires distinct partyAInfo per message, but peer may not cryptographically verify uniqueness/monotonicity beyond local policy.
- **Attacker scenario:** Replay or reuse of OtherInfo contexts → related keying material.
- **Affected goals:** FR, REPLAY
- **References:** RFC 2631 §2.4
- **Fix:** Bind transcript nonces from both parties; reject reused partyAInfo under same static pair.

### F-006 — 3DES KEK examples / short MAC in historical wrap
- **Severity:** Medium
- **Pattern IDs:** N7, C16
- **Location:** §2.1.3–2.1.4
- **Description:** Examples target 3DES KEKs; legacy wrap tags short vs 128-bit floor.
- **Attacker scenario:** Weak KEK brute force / short-tag forgery on wrap.
- **Affected goals:** KS, INT
- **References:** NIST SP 800-67; AES-KW RFC 3394
- **Fix:** AES-KeyWrap / AES-GCM; 128-bit+ tags.

## Coverage Matrix

| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| KS | No | High | Active + LT | K10, static-static, weak params |
| IND | No | High | Active | Weak ZZ |
| INT | Partial | Medium | — | Depends on KEK use |
| EA | N/A | — | — | Method is KE, not AEAD |
| MA | N/A | — | — | — |
| KA | Partial | Medium | MITM | Cert on recipient; validation optional |
| FS | No | High | LT compromise | Static-static; E-S better |
| PCS | N/A | — | — | Not claimed |
| FUT | N/A | — | — | Not claimed |
| HNDL | N/A | — | — | Classical FF only |
| DEN | N/A | — | — | — |
| ANO | N/A | — | — | — |
| REPLAY | Partial | Medium | Active | partyAInfo |
| DG | N/A | — | — | No negotiation |
| KCI | No | High | LT | Static-static DH |
| UKS | Partial | Medium | Peer | Cert binding external |
| BIND | Partial | Medium | — | OtherInfo labels |
| FR | Partial | Medium | — | partyAInfo |
| classical-param-strength | No | High | — | q≥160 |

## Catalog Checklist (highlights)

| ID | Result | Reason |
|----|--------|--------|
| K10, PV2, PV4 | **Yes** | Optional validation |
| F1, F2, A4 | **Yes** | Static-static |
| K3 | Yes | SHA-1 KDF / non-Extract |
| N7 | Yes | Weak floors, 3DES, SHA-1 |
| PQ* | N/A | No PQ |
| Other §3 | No/N/A | — |
