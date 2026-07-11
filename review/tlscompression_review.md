# Protocol Review: TLS Compression Methods (RFC 3749)

**Scope:** protocol logic only  
**Source:** `flaw-examples/tls1compression.txt` (RFC 3749)

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

Findings: 1 Critical, 0 High, 1 Medium, 0 Low, 0 Info  
Verdict: **FAIL**

RFC 3749 standardizes DEFLATE compression inside the TLS record pipeline (compress → MAC → encrypt). Length of ciphertext becomes a compression oracle (CRIME/BREACH).

## Goals, Threat Model, Invariants, Primitives, Proof Strategy

| Artifact | Summary |
|----------|---------|
| Goals | Interop compression for TLS 1.0–1.2; inherits TLS confidentiality claims |
| Threat model | Network adversary observing record lengths; active injection into compressed streams |
| Scope note | Spec only defines compression methods; security depends on TLS record ordering |
| Proof | Informal §6; acknowledges length leakage but understates exploitability |

## Findings

### F-001 — Plaintext compression before encryption (CRIME/BREACH)
- **Severity:** Critical
- **Pattern IDs:** C8
- **Location:** §2 (DEFLATE); §3 history; §6 Security Considerations; TLS record: compress then protect
- **Description:** DEFLATE is applied to TLSPlaintext before MAC/encryption. Compression ratio depends on plaintext redundancy, so encrypted length leaks whether attacker-controlled bytes match secrets in the same compression context. Stateful history (§3) improves ratio and strengthens the oracle across records within a connection.
- **Attacker scenario:** MITM or sibling-origin script varies guesses adjacent to cookies/CSRF tokens; observes compressed record sizes; recovers secrets byte-by-byte (CRIME on requests; BREACH on responses).
- **Affected goals:** IND, KS (secret recovery without breaking the cipher)
- **References:** CRIME (2012); BREACH (2013); RFC 3749 §6; TLS 1.3 removes compression (RFC 8446)
- **Fix:** Disable TLS-level compression (null only). Do not compress secrets with attacker-influenced data. Prefer TLS 1.3.

### F-002 — Spec understates residual risk when compression is enabled
- **Severity:** Medium
- **Pattern IDs:** C8, C9
- **Location:** §6
- **Description:** Security Considerations warn that length after compression may differ but frame this as a generic side channel, not a practical adaptive chosen-input oracle. No MUST-disable for secret-bearing profiles.
- **Attacker scenario:** Deployers enable DEFLATE for bandwidth, believing encryption hides content; length oracle remains.
- **Affected goals:** IND
- **References:** RFC 3749 §6
- **Fix:** Document MUST NOT use compression when PETs/secrets share a context with attacker input; default disable.

## Coverage Matrix

| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| KS | Partial | High | Active length oracle | Secrets recoverable via C8 |
| IND | No | High | Active | Length leaks plaintext structure |
| INT | N/A | — | — | Compression does not provide INT |
| EA | N/A | — | — | Inherited from TLS |
| MA | N/A | — | — | Inherited from TLS |
| KA | N/A | — | — | Not in scope |
| FS | N/A | — | — | Not in scope |
| PCS | N/A | — | — | Not in scope |
| FUT | N/A | — | — | Not in scope |
| HNDL | N/A | — | — | Not in scope |
| DEN | N/A | — | — | Not in scope |
| ANO | N/A | — | — | Not claimed |
| REPLAY | N/A | — | — | TLS record layer |
| DG | N/A | — | — | Negotiation of method is TLS HS |
| KCI | N/A | — | — | — |
| UKS | N/A | — | — | — |
| BIND | N/A | — | — | — |
| FR | N/A | — | — | — |
| classical-param-strength | N/A | — | — | — |

## Catalog Checklist

| ID | Result | Reason |
|----|--------|--------|
| C8 | **Yes** | DEFLATE before encrypt |
| C9 | Yes | Length leakage related |
| All other §3 | N/A or No | Spec is compression-only |
