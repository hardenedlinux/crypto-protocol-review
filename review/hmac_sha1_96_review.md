# Protocol Review: HMAC-SHA-1-96 (RFC 2404)

**Scope:** protocol-level design only
**Source:** RFC 2404 - The Use of HMAC-SHA-1-96 within ESP and AH (November 1998)

## Summary
Findings: 1 Critical, 0 High, 1 Medium, 0 Low, 0 Info
Verdict: FAIL

## Goals, Threat Model, Invariants, Primitives, Proof Strategy
See associated review artifacts for this protocol. This review focuses on the attack pattern checker findings.

## Findings

### F-001 — HMAC-SHA-1-96 Truncated Tag (96-bit) Below 128-bit Security Margin
- **Severity:** Critical
- **Pattern IDs:** C16
- **Location:** RFC 2404 §2, lines 90-101; Security Considerations §5
- **Description:** RFC 2404 specifies that HMAC-SHA-1-96 produces a 160-bit authenticator value but MUST truncate to 96 bits for ESP and AH. The sole justification provided is that "96 bits was selected because it is the default authenticator length as specified in [AH]" (line 99-101). This is a circular justification providing no cryptographic rationale for the truncation level. RFC 2104 permits truncation but does not mandate 96 bits as a recommended length.
- **Attacker scenario:** An attacker who can observe and manipulate IPsec packets can attempt a forgery attack on the 96-bit truncated HMAC tag. With a 96-bit authentication tag, a birthday attack requires approximately 2^48 MAC generation operations to find a collision and forge a valid packet. This is within the realm of feasible attack computation for a well-funded adversary (e.g., nation-state actors) given 1998-era analysis and becomes increasingly practical with modern GPU clusters. The truncated tag provides only 48 bits of security against birthday attacks, not the full 80 bits that SHA-1's HMAC output would theoretically provide.
- **Affected goals:** EA (entity authentication), INT (integrity), MA (message authentication)
- **References:** RFC 2404 §2, RFC 2104 §3; Bellare et al. "Keying Hash Functions for Message Authentication" Crypto 96; Birthday attack complexity analysis
- **Fix:** Use full 128-bit or 160-bit HMAC output, or transition to a modern AEAD such as AES-GCM (RFC 4106) or ChaCha20-Poly1305 (RFC 7539) which provide 128-bit authentication tags. If bandwidth constraints require truncation, explicit security justification must be provided demonstrating that 96 bits provides adequate security for the specific protocol threat model.

### F-002 — Security Claims Based on Pre-SHA-1-Collision-Discovery Analysis
- **Severity:** Medium
- **Pattern IDs:** C16, I1
- **Location:** RFC 2404 §5 (Security Considerations), lines 177-188
- **Description:** The security considerations in RFC 2404 state "At the time of this writing there are no practical cryptographic attacks against HMAC-SHA-1-96" and claim that birthday attacks are impractical requiring 2^80 block processing. This analysis predates the discovery of SHA-1 collisions (Wang et al., 2005) and does not account for the later SHAttered attack (2017). While HMAC-SHA-1 remains structurally different from SHA-1 (requiring key knowledge for collision attacks), the protocol was designed with an outdated security assumption.
- **Attacker scenario:** An attacker with knowledge of SHA-1's weaknesses may attempt to exploit any reduction in HMAC-SHA-1's security margin. Although HMAC with a keyed secret is not directly vulnerable to the same collision attacks as plain SHA-1, the reduced effective security from the 96-bit truncation remains the primary concern.
- **Affected goals:** EA, INT, KS (key separation concerns for legacy implementations)
- **References:** RFC 2404 §5; Wang et al. "Finding Collisions in the Full SHA-1" (Crypto 2005); Shattered attack (2017) - Google Security Team
- **Fix:** Deprecate HMAC-SHA-1-96 for new implementations. Transition to HMAC-SHA-256/384/512 or AEAD constructions with 128-bit minimum tags.

## Coverage Matrix
| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| EA (Entity Auth) | Partial | Low | MITM in scope | 96-bit tag weakens authentication |
| INT (Integrity) | Partial | Low | Active tamper | Birthday attack at 2^48 weakens integrity |
| MA (Message Auth) | Partial | Low | Forger | Same as above |
| KS (Key Separation) | Yes | Medium | Key reuse | Per-SA keys enforced by IPsec |

## Attack Pattern Checklist (C16 Focus)

| Pattern | Result | Notes |
|---------|--------|-------|
| C16 — AEAD tag truncated below 128 bits | **YES** | 96-bit truncation with only "AH default" justification; birthday attack at 2^48 |
| C1 — Nonce reuse | N/A | HMAC is not an AEAD; IPSec handles IV/nonce separately |
| C2 — CBC without MAC | N/A | HMAC-SHA-1-96 is used for authentication, ESP handles encryption |
| C10 — Same key for both directions | No | Per-direction SA keys in IPsec |
| C14 — AEAD lacks key commitment | No | HMAC-SHA-1-96 provides authentication with distinct SA keys |

## Appendix: Truncation Analysis

RFC 2104 states truncation is permissible but recommends t >= 128 bits for collision-resistant hashes. HMAC-SHA-1 produces 160-bit output; truncating to 96 bits loses 64 bits of output, reducing birthday collision security from 80 bits to 48 bits (2^48 MAC operations to find a collision).

The selection criteria in RFC 2404 was "fit the AH field" not "meet security requirements" — this is the core protocol-level flaw per C16.

(End of file)
