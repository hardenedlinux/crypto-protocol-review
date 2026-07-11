# Protocol Review: HMAC-SHA-1-96 within ESP and AH (RFC 2404)

**Scope:** protocol logic only  
**Source:** `flaw-examples/ipsec_hmac.txt` (RFC 2404)

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

Findings: 0 Critical, 0 High, 2 Medium, 1 Low, 0 Info  
Verdict: **PASS-WITH-FIXES**

RFC 2404 specifies HMAC-SHA-1 truncated to 96 bits for IPsec ICV. Per SKILL.md C16: unjustified tags in 64–96-bit range default to **Medium** (online forgery ~2^{96}, not a 2^{48} birthday bound). SHA-1-as-HMAC-MAC is legacy interop (Low) unless used collision-sensitively as hash/KDF.

## Goals, Threat Model, Invariants, Primitives, Proof Strategy

| Artifact | Summary |
|----------|---------|
| Goals | Data origin authentication + integrity for ESP/AH |
| Primitives | HMAC-SHA-1, truncate to 96 bits; key ≥160 bits recommended |
| Threat model | Online forger under SA key; passive observer |
| Proof | Informal §5 (pre-dates modern SHA-1 collision results; HMAC still keyed) |

## Findings

### F-001 — 96-bit truncated authenticator below 128-bit floor
- **Severity:** Medium
- **Pattern IDs:** C16
- **Location:** §2 (96-bit truncation); §5 Security Considerations
- **Description:** HMAC-SHA-1 produces 160 bits; ESP/AH MUST use leftmost 96 bits. Justification is AH default field size, not a cryptographic bound. Online forgery cost ≈2^96 verifications under the SA key — below the skill’s 128-bit tag target without explicit residual-risk acceptance.
- **Attacker scenario:** On-path adversary submits forged packets with random ICVs until one verifies (~2^96 attempts). Impractical for most adversaries today but fails modern tag-length policy.
- **Affected goals:** INT, MA, EA
- **References:** RFC 2404 §2, §5; RFC 2104; SKILL.md C16
- **Fix:** Use HMAC-SHA-256 with ≥128-bit truncation or AEAD (AES-GCM) with 128-bit tags.

### F-002 — SHA-1 legacy profile for new deployments
- **Severity:** Medium
- **Pattern IDs:** N7
- **Location:** Entire document; §5
- **Description:** Spec freezes SHA-1 as the hash in HMAC. §2.8 allows HMAC-SHA-1 as MAC for legacy interop (Low alone) but flags profiles that still mandate it for new sessions without stronger alternatives as design smell; combined with fixed 96-bit trunc → Medium.
- **Attacker scenario:** Policy/compliance forces continued use; reduced future margin if HMAC-SHA-1 assumptions weaken.
- **Affected goals:** MA (margin)
- **References:** NIST SP 800-131A; SHAttered (context: raw SHA-1, not direct HMAC break)
- **Fix:** Prefer HMAC-SHA-256+; deprecate SHA-1 ICVs for new SAs.

### F-003 — Security considerations claim birthday 2^80 without tag-length policy
- **Severity:** Low
- **Pattern IDs:** C16
- **Location:** §5
- **Description:** Text discusses 2^80 birthday on full HMAC-SHA-1 and calls attacks impractical, but does not analyze 96-bit truncation against a 128-bit integrity target or multi-user settings.
- **Attacker scenario:** Deployers overestimate integrity level from §5 prose.
- **Affected goals:** INT (documentation)
- **References:** RFC 2404 §5
- **Fix:** Document explicit tag-length security level (96-bit online) and migration path.

## Coverage Matrix

| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| KS | N/A | — | — | MAC-only algorithm profile |
| IND | N/A | — | — | — |
| INT | Partial | High | Online forger | 96-bit tag |
| EA | Partial | High | Online forger | Same |
| MA | Partial | High | Online forger | Same |
| KA | N/A | — | — | — |
| FS | N/A | — | — | — |
| PCS | N/A | — | — | — |
| FUT | N/A | — | — | — |
| HNDL | N/A | — | — | — |
| DEN | N/A | — | — | — |
| ANO | N/A | — | — | — |
| REPLAY | N/A | — | — | ESP/AH seq separate |
| DG | N/A | — | — | — |
| KCI | N/A | — | — | — |
| UKS | N/A | — | — | — |
| BIND | N/A | — | — | — |
| FR | N/A | — | — | — |
| classical-param-strength | Partial | Medium | — | SHA-1 HMAC legacy |

## Catalog Checklist (highlights)

| ID | Result | Reason |
|----|--------|--------|
| C16 | **Yes** | 96-bit truncation |
| N7 | Yes | SHA-1 still the only hash in profile |
| C1–C15 | N/A | Not an encryption mode |
| Other §3 | N/A or No | Algorithm profile only |
