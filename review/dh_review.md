# Protocol Review: Diffie-Hellman Key Agreement Method (RFC 2631)

**Scope:** protocol logic only  
**Source:** RFC 2631 (flaw-examples/dh_key_agreement.txt)

## Summary
Findings: 1 Critical, 1 High, 2 Medium, 0 Low, 0 Info  
Verdict: FAIL

## Goals, Threat Model, Invariants, Primitives, Proof Strategy
See goals.md, threat-model.md, invariants.md, primitives.md, proof-sketch.md.

## Findings

### F-001 — Small Subgroup Attack (K10) Due to Optional Public Key Validation
- **Severity:** Critical
- **Pattern IDs:** K10, PV2, PV4
- **Location:** §2.1.5 (Public Key Validation); §2.3 (Ephemeral-Static mode); §2.4 (Static-Static mode)
- **Description:** RFC 2631 defines public key validation as an optional ("MAY be used") check. The validation consists of: (1) verify y ∈ [2, p−1], and (2) verify y^q mod p == 1. In Ephemeral-Static mode, the recipient "SHOULD" perform validation (§2.3). In Static-Static mode, both parties "SHOULD" perform validation or rely on CA verification (§2.4). Since validation is not mandatory (MUST NOT be omitted), an attacker who is an active MITM can inject a small-order public key, forcing the shared secret ZZ into a small subgroup of size << q, which trivially breaks the key agreement. The protocol acknowledges this attack in the Security Considerations section (§"Static Diffie-Hellman keys are vulnerable to a small subgroup attack") but only recommends (SHOULD), not mandates (MUST), validation.
- **Attacker scenario:** An active MITM attacker intercepts the DH exchange. Instead of forwarding the honest party's public key yb, the attacker substitutes yb' = g^s mod p where s is chosen so that yb' has small order (e.g., order 2, 4, or q's small factors). When the honest party computes ZZ = (yb')^xa mod p, the result lies in the small subgroup controlled by the attacker, who can then recover ZZ and any derived keys.
- **Affected goals:** KA (key agreement), KS (key secrecy), IND (indistinguishability), FS (forward secrecy)
- **References:** RFC 2631 §2.1.5, §2.3, §2.4, Security Considerations; [LAW98] L. Law et al., "An efficient protocol for authenticated key agreement"; [LL97] C.H. Lim and P.J. Lee, "A key recovery attack on discrete log-based schemes using a prime order subgroup" (Crypto '97)
- **Fix:** Change public key validation from "MAY be used" to "MUST be performed" for all DH public keys received over the network. Alternatively, generate keys that are inherently resistant to small subgroup attacks as described in [LL97].

### F-002 — Weak Hash Function in Key Derivation (SKILL.md §2.8)
- **Severity:** High
- **Pattern IDs:** (Primitive selection — out-of-scope catalog section)
- **Location:** §2.1.2 (Generation of Keying Material)
- **Description:** RFC 2631 specifies SHA-1 (FIPS-180) as the hash function H for deriving keying material: KM = H(ZZ || OtherInfo). SHA-1 is deprecated for cryptographic use due to known collision attacks (Shattered, 2017). While no practical collision attack against HMAC-SHA-1 is known, the use of SHA-1 in a KDF construction is a design smell and may fail modern compliance requirements (NIST SP 800-131A Rev. 2 recommends SHA-256 or stronger).
- **Attacker scenario:** Not directly exploitable with current known attacks on HMAC-SHA-1, but the weakness in SHA-1 weakens the overall security margin. A breakthrough in SHA-1 cryptanalysis could compromise the key derivation.
- **Affected goals:** KS (key secrecy)
- **References:** FIPS-180 (SHA-1); NIST SP 800-131A Rev. 2; SHA-1 collision (Shattered, 2017)
- **Fix:** Replace SHA-1 with SHA-256 or SHA-384 in the key derivation. The fix is backward-compatible if both parties update their implementation.

### F-003 — Weak 3DES Key Wrapping with Short MAC Tags
- **Severity:** Medium
- **Pattern IDs:** C16 (truncated MAC), C10 (same key used for both directions)
- **Location:** §2.1.3 (KEK Computation), §2.1.4 (Keylengths)
- **Description:** RFC 2631 specifies 3-key 3DES-EDE for key wrapping with only a 64-bit MAC in the inner CBC structure (per the CMS "key wrap" algorithm). The 3DES effective key space is only ~112 bits due to meet-in-the-middle, and 64-bit MAC tags are below the 128-bit threshold recommended for modern AEADs. Additionally, the KEK derivation uses the same key material for both directions (K1, K2, K3 derived from KM blocks are used for both wrap and unwrap operations in 3DES-EDE).
- **Attacker scenario:** A birthday-parity attack on the 64-bit MAC could enable forgery of key wrap data within 2^32 operations. The weak 3DES key is also vulnerable to brute-force search given sufficient ciphertext.
- **Affected goals:** INT (integrity), KS (key secrecy)
- **References:** NIST SP 800-67 (3DES); RFC 3394 (AES Key Wrap); C16 (SKILL.md)
- **Fix:** Migrate to AES-128 or AES-256 in GCM mode (AES-GCM provides both encryption and authentication with 128-bit tags). Use per-direction key labels in the KDF to derive distinct KEKs for each direction.

### F-004 — No Mandatory Fresh Ephemeral Contribution Per Session
- **Severity:** Medium
- **Pattern IDs:** F1 (No ephemeral contribution to session key), F3 (No fresh DH per message)
- **Location:** §2.3 (Ephemeral-Static mode), §2.4 (Static-Static mode)
- **Description:** In Static-Static mode (§2.4), both parties use long-term static DH key pairs. Since the same key pairs are reused across sessions, ZZ is identical across sessions unless partyAInfo differs. The specification requires partyAInfo to be different per message, but the entropy still derives solely from the static DH values and partyAInfo (which is chosen by the sender, not both parties). There is no per-message fresh DH contribution from the ephemeral component, unlike Ephemeral-Static mode where the sender generates a new ephemeral key pair per message. This means each session's ZZ is not independently generated from fresh randomness contributed by both parties.
- **Attacker scenario:** If partyAInfo is leaked or predictable across sessions, an attacker who has captured a prior session's ZZ and partyAInfo can derive subsequent session keys, compromising forward secrecy for those sessions.
- **Affected goals:** FS (forward secrecy), PCS (post-compromise security)
- **References:** SKILL.md F1, F3
- **Fix:** Use Ephemeral-Static mode (mandatory per §2.3) for all sessions requiring forward secrecy. Alternatively, introduce a mandatory fresh ephemeral contribution from both parties (e.g., a DH key exchange with both sides generating ephemerals) to achieve contributory agreement per session.

## Coverage Matrix

| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| KA (key agreement) | Partial | High | MITM attacker | K10 vulnerability allows forced small-subgroup ZZ |
| KS (key secrecy) | Partial | Medium | Passive/active | SHA-1 KDF weakens margin; small-subgroup can expose ZZ |
| IND (indistinguishability) | Partial | Medium | MITM attacker | Key derivation from small-subgroup ZZ is breakable |
| INT (integrity) | Partial | Medium | Forger | 64-bit MAC tag in 3DES key wrap is below modern standard |
| FS (forward secrecy) | No | High | Session key exposure | Static-static mode has no ephemeral contribution per session |
| PCS (post-compromise) | No | High | Long-term key exposure | No ratchet or healing mechanism |
| EA (entity authentication) | Yes | High | MITM attacker | Static certificates provide authentication in both modes |
| KCI (key compromise impersonation) | Yes | High | Long-term key exposure | Static DH does not prevent KCI |
| UKS (unknown key-share) | No | Medium | Malicious peer | No explicit UKS protection documented |
| REPLAY | Partial | High | Replay attacker | partyAInfo required per-message in static-static but not validated |
