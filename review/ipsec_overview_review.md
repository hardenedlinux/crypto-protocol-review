# Protocol Review: ESP NULL Encryption (RFC 2410)

**Scope:** protocol logic only  
**Source:** `flaw-examples/ipsec_ah_esp.txt` (RFC 2410)

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

Findings: 0 Critical, 0 High, 2 Medium, 2 Low, 1 Info  
Verdict: **PASS-WITH-FIXES**

ESP_NULL is the identity transform: no confidentiality by design. Acceptable only when strong authentication is mandated and operators understand the non-goal. Residual risk is misconfiguration (NULL+weak/NULL auth) and weaker header coverage than AH.

## Goals, Threat Model, Invariants, Primitives, Proof Strategy

| Artifact | Summary |
|----------|---------|
| Goals | Enable ESP without encryption (auth-only ESP); interoperability |
| Non-goals | Confidentiality |
| Constraint | RFC 2406: conf and auth MUST NOT both be NULL |
| Proof | Explicit security note §4 |

## Findings

### F-001 — Zero confidentiality (by design; misconfiguration risk)
- **Severity:** Medium
- **Pattern IDs:** C2
- **Location:** §2 NULL(b)=b; §4 Security Considerations
- **Description:** Ciphertext equals plaintext. Spec correctly states no confidentiality. Severity Medium reflects deployment footgun when operators expect “ESP ⇒ encrypted.”
- **Attacker scenario:** Passive read of all application data on ESP_NULL SAs.
- **Affected goals:** KS, IND (not provided)
- **References:** RFC 2410 §4
- **Fix:** Document non-goal in policy; alert on ESP_NULL in production unless auth-only is explicit.

### F-002 — Depends on strong authentication; protocol does not enforce strength
- **Severity:** Medium
- **Pattern IDs:** A1, C2
- **Location:** §4 (“imperative… strong encryption or strong authentication”)
- **Description:** Security relies on ESP auth algorithm strength. Framework allows weak MACs; imperative is advisory prose, not a machine-checkable mandate of algorithm strength.
- **Attacker scenario:** ESP_NULL + weak/truncated MAC → cleartext + forgery.
- **Affected goals:** INT, MA
- **References:** RFC 2410 §4; RFC 2406
- **Fix:** Policy: ESP_NULL only with ≥128-bit ICV / modern MAC; ban NULL auth.

### F-003 — ESP_NULL does not authenticate outer IP header like AH
- **Severity:** Low
- **Pattern IDs:** — (scope vs AH)
- **Location:** §1 comparison to AH
- **Description:** ICV covers ESP payload fields, not the outer IP header immutable set AH would cover.
- **Attacker scenario:** Outer header manipulation without ESP ICV failure (routing/QoS games).
- **Affected goals:** INT (header)
- **References:** RFC 2410 §1; RFC 2402
- **Fix:** Use AH or tunnel mode when outer/inner header auth required.

### F-004 — Combined-mode composition deferred to ESP
- **Severity:** Low
- **Pattern IDs:** C2, C3
- **Location:** §1 references to ESP combined use
- **Description:** NULL profile does not restate EtM ordering; implementers must follow RFC 2406 (encrypt then auth). Risk is documentation gap, not a new algorithm.
- **Attacker scenario:** Wrong composition if implementer ignores ESP base spec.
- **Affected goals:** INT, EA
- **References:** RFC 2406 §3.3.2
- **Fix:** Normative cross-ref: MUST implement ESP processing order.

### F-005 — No IV/key material (stateless)
- **Severity:** Info
- **Pattern IDs:** —
- **Location:** §2.2
- **Description:** Correct for identity transform; N/A for C1.
- **Attacker scenario:** N/A
- **Affected goals:** —
- **References:** RFC 2410 §2
- **Fix:** None.

## Coverage Matrix

| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| KS | No | High | Passive | By design |
| IND | No | High | Passive | By design |
| INT | Partial | Medium | Active | Requires strong ESP auth |
| EA | Partial | Medium | Active | Same |
| MA | Partial | Medium | Active | Same |
| KA | N/A | — | — | — |
| FS | N/A | — | — | No conf |
| PCS | N/A | — | — | — |
| FUT | N/A | — | — | — |
| HNDL | N/A | — | — | — |
| DEN | N/A | — | — | — |
| ANO | N/A | — | — | Cleartext |
| REPLAY | Partial | Medium | Network | ESP seq + auth |
| DG | N/A | — | — | — |
| KCI | N/A | — | — | — |
| UKS | N/A | — | — | — |
| BIND | N/A | — | — | — |
| FR | Partial | Medium | — | Seq |
| classical-param-strength | N/A | — | — | Depends on auth alg |

## Catalog Checklist (highlights)

| ID | Result | Reason |
|----|--------|--------|
| C2 | Yes (expected) | No encryption |
| A1 | Partial | Auth strength not enforced |
| C1 | N/A | No IV |
| Other §3 | N/A or No | — |
