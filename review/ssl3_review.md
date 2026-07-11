# Protocol Review: SSL 3.0 (RFC 6101)

**Scope:** protocol logic only  
**Source:** `flaw-examples/ssl3_rfc6101.txt` (RFC 6101)

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

Findings: 4 Critical, 3 High, 3 Medium, 2 Low, 1 Info  
Verdict: **FAIL**

SSL 3.0 is structurally broken for modern use: MAC-then-encrypt CBC (POODLE), RSA-PKCS#1 v1.5 key transport, export/NULL suites, MD5/SHA-1 ad-hoc KDFs, and weak negotiation binding relative to TLS 1.3.

## Goals, Threat Model, Invariants, Primitives, Proof Strategy

| Artifact | Summary |
|----------|---------|
| Goals | KS, IND, INT, EA, MA, KA (server auth), REPLAY, DG; FS only for ephemeral DH suites; no PCS/HNDL/DEN/ANO claim |
| Threat model | Dolev-Yao network; passive + active MITM; long-term RSA/DH compromise for FS analysis |
| Handshake | ClientHello → ServerHello/Cert/KeyExchange → ClientKeyExchange → ChangeCipherSpec → Finished (mutual) |
| Primitives | RC4, DES/3DES/IDEA CBC, MD5/SHA-1 MAC and KDF; RSA PKCS#1 v1.5; optional DH/DHE |
| Proof | Informal only (Appendix F) |

## Findings

### F-001 — MAC-then-encrypt CBC enables POODLE
- **Severity:** Critical
- **Pattern IDs:** C2, C3, I3
- **Location:** §5.2.3.1–5.2.3.2 (GenericStreamCipher / GenericBlockCipher)
- **Description:** Records compute MAC over plaintext, then encrypt MAC‖plaintext‖padding. SSL 3.0 padding is not deterministic content-checked padding (unlike TLS); the last byte is the padding length only. This creates a reliable padding oracle.
- **Attacker scenario:** MITM rewrites CBC ciphertext and observes `bad_record_mac` vs success to recover plaintext bytes (~256 trials/byte) — POODLE (CVE-2014-3566).
- **Affected goals:** IND, EA, INT
- **References:** Moeller et al., POODLE (2014); CVE-2014-3566; RFC 6101 §5.2.3.2
- **Fix:** Disable SSL 3.0; use TLS 1.2+ AEAD (or at least Encrypt-then-MAC). Never offer SSL 3.0.

### F-002 — RSA-PKCS#1 v1.5 premaster encryption (Bleichenbacher class)
- **Severity:** Critical
- **Pattern IDs:** C15, F1
- **Location:** §5.6.7.1 EncryptedPreMasterSecret
- **Description:** Client encrypts 48-byte premaster under the server’s long-term RSA key with PKCS#1 v1.5. No FS under LT RSA compromise; padding oracles enable PMS recovery.
- **Attacker scenario:** (1) Harvest ciphertext, later steal server RSA key → decrypt all past RSA sessions. (2) Adaptive padding queries → ROBOT-class recovery of PMS.
- **Affected goals:** KS, FS, IND
- **References:** Bleichenbacher (1998); ROBOT (2017); RFC 6101 §5.6.7.1
- **Fix:** Remove static RSA key transport; use ephemeral DH/ECDHE + AEAD (TLS 1.3 model).

### F-003 — Export and NULL cipher suites remain defined
- **Severity:** Critical
- **Pattern IDs:** N7, R4, K3
- **Location:** Appendix A / cipher suite registry (export RC4-40, DES-40, NULL-MD5, etc.)
- **Description:** Protocol defines export-grade and NULL suites. If offered/accepted, effective key strength collapses (40-bit) or confidentiality is absent.
- **Attacker scenario:** FREAK-class strip/force to export RSA or 40-bit ciphers; offline break of session keys.
- **Affected goals:** KS, IND, DG
- **References:** FREAK (CVE-2015-0204); RFC 6101 suite tables
- **Fix:** Never implement/offer export or NULL suites; hard-fail if peer selects them.

### F-004 — Version / cipher negotiation strip without modern downgrade defense
- **Severity:** Critical
- **Pattern IDs:** N1, N3, R3, R4
- **Location:** §5.6.1 ClientHello/ServerHello; Appendix E (SSL 2.0 compat); §F.1.2
- **Description:** ClientHello cipher list and version are cleartext. MITM can strip strong suites or force SSL 2.0-compatible ClientHello. Finished binds the *modified* transcript both sides saw, so strip is undetectable as inconsistency. RSA PMS carries `client_version` but that only helps after RSA decrypt and only for RSA KE.
- **Attacker scenario:** Strip modern suites → force export/RC4/SSL 2.0 path; complete handshake under weak crypto.
- **Affected goals:** DG, KS, BIND
- **References:** RFC 6101 §F.1.2, Appendix E; POODLE downgrade path
- **Fix:** TLS 1.3-style `supported_versions` + transcript-bound selection; disable SSL 2.0/3.0.

### F-005 — RC4 stream suites with continuous keystream
- **Severity:** High
- **Pattern IDs:** C6
- **Location:** §5.2.3.1 GenericStreamCipher; RC4 suites
- **Description:** RC4 state continues across records; known biases enable plaintext recovery at scale.
- **Attacker scenario:** Collect many sessions/cookies under RC4; statistical recovery (RC4 NOMORE).
- **Affected goals:** IND, KS
- **References:** Fluhrer-Mantin-Shamir; AlFardan et al.; RFC 7465 (prohibits RC4)
- **Fix:** Remove RC4; use AEAD only.

### F-006 — Static RSA / static DH: no handshake-ephemeral FS
- **Severity:** High
- **Pattern IDs:** F1, F2
- **Location:** RSA and DH_* (non-ephemeral) suites
- **Description:** Session secrets recoverable from long-term decryption/static DH keys alone.
- **Attacker scenario:** Record traffic; compromise server LT key later → decrypt history.
- **Affected goals:** FS, KS
- **References:** RFC 6101 key-exchange modes
- **Fix:** Mandate DHE (and modern curves/groups); drop static RSA/DH KE.

### F-007 — Session resumption reuses master_secret without fresh KE
- **Severity:** High
- **Pattern IDs:** F8, R8
- **Location:** §5.5 abbreviated handshake; §F.1.4
- **Description:** Resumption reuses `master_secret`; new randoms only re-expand keys. No FS vs master_secret compromise; limited context binding vs modern ticket binders.
- **Attacker scenario:** Steal session cache entry / master_secret → decrypt all resumed sessions.
- **Affected goals:** FS, REPLAY, BIND
- **References:** RFC 6101 §F.1.4
- **Fix:** TLS 1.3 PSK-(EC)DHE resumption; bind full auth context; short lifetimes.

### F-008 — Ad-hoc MD5+SHA-1 master_secret / key_block KDF
- **Severity:** Medium
- **Pattern IDs:** K1, K3, I1
- **Location:** §6.1–6.2
- **Description:** Cascaded MD5/SHA with letter prefixes — not HKDF; MD5 collision-prone; non-uniform DH IKM not extracted with a modern PRF.
- **Attacker scenario:** Weakens margin if hash/PRF assumptions fail; export paths further reduce entropy.
- **Affected goals:** KS
- **References:** RFC 6101 §6.1; RFC 6151
- **Fix:** HKDF-SHA-256+ with domain-separated labels.

### F-009 — Compression before encryption allowed
- **Severity:** Medium
- **Pattern IDs:** C8
- **Location:** §5.2.2; ClientHello compression_methods
- **Description:** Optional compression prior to MAC/encrypt leaks plaintext via length (CRIME-class).
- **Attacker scenario:** Force/enable compression; oracle secrets via size changes.
- **Affected goals:** IND
- **References:** CRIME (2012); RFC 6101 §5.2.2
- **Fix:** Null compression only (TLS 1.3 removes compression).

### F-010 — Anonymous DH suites (no peer auth)
- **Severity:** Medium
- **Pattern IDs:** A1
- **Location:** SSL_DH_anon_* suites
- **Description:** Intentional lack of authentication → trivial MITM if suite selected.
- **Attacker scenario:** MITM separate DH with each party.
- **Affected goals:** KA, MA, BIND
- **References:** §F.1.1.1
- **Fix:** Disable anonymous suites.

### F-011 — Finished uses dual MD5/SHA-1 construction
- **Severity:** Low
- **Pattern IDs:** CP5, I1
- **Location:** §5.6.9
- **Description:** Transcript MAC is ad-hoc nested MD5/SHA, not HMAC; collision resistance below modern 128-bit targets if MD5/SHA-1 break.
- **Attacker scenario:** Theoretical transcript collision / MAC forge under hash breaks.
- **Affected goals:** MA, BIND
- **References:** §5.6.9, §F.1.5
- **Fix:** HMAC/HKDF transcript (TLS 1.2+/1.3).

### F-012 — Alerts often cleartext / distinguishable
- **Severity:** Low
- **Pattern IDs:** M4
- **Location:** §5.3 Alerts
- **Description:** Pre-CCS and some failure paths leak alert types usable as oracles (padding/MAC).
- **Attacker scenario:** Distinguish bad_record_mac vs other fatals for oracle attacks.
- **Affected goals:** IND (via oracle)
- **References:** POODLE/Lucky13-class use of alerts
- **Fix:** Uniform encrypted alerts; constant-time reject (impl) + AEAD (design).

### F-013 — No HNDL / PQ path
- **Severity:** Info
- **Pattern IDs:** F6
- **Location:** Entire suite set
- **Description:** Classical-only; HNDL not claimed — Info only.
- **Attacker scenario:** Harvest-now decrypt-later under CRQC.
- **Affected goals:** HNDL (unclaimed)
- **References:** —
- **Fix:** Migrate to TLS 1.3 hybrid KE if HNDL is a goal.

## Coverage Matrix

| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| KS | No | High | MITM + LT compromise | F-001–F-003 |
| IND | No | High | Active network | POODLE, RC4, compression |
| INT | No | High | Active | MtE CBC |
| EA | No | High | Active | C2/C3 |
| MA | Partial | Medium | Active | Finished present; weak PRF |
| KA | Partial | High | MITM | Server cert when non-anon |
| FS | Partial | High | LT key compromise | Only DHE suites |
| PCS | N/A | — | — | Not claimed |
| FUT | N/A | — | — | Not claimed |
| HNDL | N/A | — | — | Unclaimed classical-only |
| DEN | N/A | — | — | Not claimed |
| ANO | N/A | — | — | Not claimed |
| REPLAY | Partial | High | Network | seq nums; resumption weak |
| DG | No | High | MITM | N1/N3/R3/R4 |
| KCI | Partial | Medium | LT compromise | Static modes |
| UKS | Partial | Medium | Malicious peer | Cert name checks external |
| BIND | Partial | Medium | MITM | Finished binds modified transcript |
| FR | Yes | High | Network | Client/Server random |
| classical-param-strength | No | High | — | Export/DES/RC4 |

## Catalog Checklist (selected; full §3 applied)

| ID | Result | Reason |
|----|--------|--------|
| A1 | Yes | DH_anon |
| A2–A9 | No/N/A | Cert suites bind identity; no TOFU model |
| C2,C3,C6,C8,C15 | Yes | MtE CBC, RC4, compression, PKCS#1 v1.5 |
| C16 | N/A | Full MD5/SHA MAC sizes (not truncated-96 profile) |
| F1,F2,F8 | Yes | Static RSA/DH; resumption |
| F3–F5,F9 | N/A | Session protocol, not messaging ratchet |
| F6 | N/A | HNDL unclaimed → Info F-013 only |
| N1,N3,N7,R3,R4 | Yes | Negotiation / export |
| R7/R7b | N/A | No 0-RTT |
| K11 | No | Finished is key confirmation |
| PQ* | N/A | No PQ |
| All other §3 | No/N/A | Not applicable or not triggered |
