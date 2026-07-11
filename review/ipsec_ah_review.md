# Protocol Review: IPsec AH (RFC 2402)

**Scope:** protocol logic only  
**Source:** `flaw-examples/ipsec_ah.txt` (RFC 2402)

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

Findings: 0 Critical, 0 High, 3 Medium, 2 Low, 1 Info  
Verdict: **PASS-WITH-FIXES**

AH intentionally provides integrity/data-origin authentication only (no confidentiality). Residual issues: 96-bit ICVs, legacy HMAC-MD5/SHA-1, optional anti-replay, and cleartext metadata. Do not score missing encryption as Critical — it is by design (pair with ESP for conf).

## Goals, Threat Model, Invariants, Primitives, Proof Strategy

| Artifact | Summary |
|----------|---------|
| Goals | Connectionless integrity, data-origin authentication; optional anti-replay |
| Non-goals | Confidentiality (explicit) |
| Threat model | Active packet modification/injection; replay |
| Primitives | HMAC-MD5-96, HMAC-SHA-1-96 MTI |
| Proof | Informal |

## Findings

### F-001 — 96-bit ICV truncation
- **Severity:** Medium
- **Pattern IDs:** C16
- **Location:** §2.2, §2.6; HMAC-*-96 profiles
- **Description:** Standard ICV is 96 bits. Online forgery cost ~2^96 (not birthday 2^48 — MAC forgery is not a collision search on the tag alone). Below modern 128-bit tag floor without explicit threat-model justification.
- **Attacker scenario:** Online attempt to forge AH ICV under known SPI/seq constraints (~2^96 queries).
- **Affected goals:** INT, MA
- **References:** RFC 2402; RFC 2403/2404; SKILL.md C16 severity: Medium for 64–96-bit tags
- **Fix:** Prefer ≥128-bit ICV (HMAC-SHA-256-128+) or AEAD ESP.

### F-002 — Legacy MTI algorithms (HMAC-MD5-96, HMAC-SHA-1-96)
- **Severity:** Medium
- **Pattern IDs:** N7
- **Location:** §5; [MG97a]/[MG97b]
- **Description:** MD5/SHA-1 based MACs remain mandatory-to-implement. HMAC-SHA-1 as MAC is legacy-interop (Low smell alone); combined with 96-bit truncation and MD5 MTI → Medium.
- **Attacker scenario:** Compliance forces weak algorithms; future cryptanalysis reduces margin.
- **Affected goals:** MA, INT (margin)
- **References:** NIST SP 800-131A; RFC 2402 §5
- **Fix:** HMAC-SHA-256/384/512; deprecate MD5.

### F-003 — Anti-replay optional at receiver
- **Severity:** Medium
- **Pattern IDs:** R9
- **Location:** §2.5, §3.3.2, §3.4.3
- **Description:** Anti-replay default assumed by sender but receiver may disable; min window 32.
- **Attacker scenario:** Replay AH packets when anti-replay disabled.
- **Affected goals:** REPLAY
- **References:** RFC 2402 §3.4.3
- **Fix:** Mandate anti-replay for unicast; larger windows.

### F-004 — Mutable IP fields not covered by ICV
- **Severity:** Low
- **Pattern IDs:** R9
- **Location:** §3.3.3.1
- **Description:** TOS/TTL/checksum etc. zeroed for ICV — intentional for transit mutability; integrity of those fields not provided.
- **Attacker scenario:** Modify TTL/TOS without ICV failure (expected limitation).
- **Affected goals:** INT (header subset)
- **References:** RFC 2402 §3.3.3
- **Fix:** Tunnel mode for inner-header integrity; accept outer mutable fields as unauthenticated.

### F-005 — No confidentiality (by design)
- **Severity:** Low
- **Pattern IDs:** M1
- **Location:** §1
- **Description:** Payload and much metadata remain cleartext. Not a defect if AH-only is intentional; Info/Low when deployments expect conf.
- **Attacker scenario:** Passive read of application data on AH-only SA.
- **Affected goals:** KS/IND (not claimed for AH)
- **References:** RFC 2402 §1; RFC 2401
- **Fix:** Use ESP (or AH+ESP) when confidentiality required.

### F-006 — SPI and sequence visible
- **Severity:** Info
- **Pattern IDs:** M1
- **Location:** §2.4–2.5
- **Description:** SA demux and ordering fields clear — normal for IPsec; ANO not claimed.
- **Attacker scenario:** Flow correlation via SPI.
- **Affected goals:** ANO (unclaimed)
- **References:** —
- **Fix:** N/A unless anonymity is a goal.

## Coverage Matrix

| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| KS | N/A | — | — | Conf not a goal |
| IND | N/A | — | — | Conf not a goal |
| INT | Partial | High | Active | 96-bit ICV; mutable fields |
| EA | Partial | High | Active | Auth yes; tag length |
| MA | Partial | High | Active | Same |
| KA | N/A | — | — | IKE |
| FS | N/A | — | — | — |
| PCS | N/A | — | — | — |
| FUT | N/A | — | — | — |
| HNDL | N/A | — | — | — |
| DEN | N/A | — | — | — |
| ANO | N/A | — | — | Unclaimed |
| REPLAY | Partial | High | Network | Optional |
| DG | N/A | — | — | — |
| KCI | N/A | — | — | — |
| UKS | N/A | — | — | — |
| BIND | Partial | Medium | — | SPI/SA |
| FR | Partial | High | — | Seq |
| classical-param-strength | Partial | Medium | — | MD5/SHA-1-96 |

## Catalog Checklist (highlights)

| ID | Result | Reason |
|----|--------|--------|
| C16 | **Yes** | 96-bit ICV |
| R9 | Yes | Optional anti-replay |
| N7 | Yes | MD5/SHA-1 MTI |
| C2 | N/A | No encryption service |
| F1 | N/A | No conf FS claim |
| M1 | Info | Cleartext by design |
| Other §3 | No/N/A | — |
