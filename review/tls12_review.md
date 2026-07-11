# Protocol Review: TLS 1.2 (RFC 5246)

**Scope:** protocol logic only  
**Source:** `flaw-examples/tls12_rfc5246.txt` (RFC 5246)

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

Findings: 4 Critical, 5 High, 3 Medium, 2 Low, 1 Info  
Verdict: **FAIL**

TLS 1.2 improves IVs and PRF flexibility over TLS 1.1 but retains static RSA/DH key exchange, CBC MAC-then-encrypt, RC4, renegotiation splice risk (without RFC 5746 binding), and resumption without modern context binders.

## Goals, Threat Model, Invariants, Primitives, Proof Strategy

| Artifact | Summary |
|----------|---------|
| Goals | KS, IND, INT, EA, MA, KA (server; optional client), REPLAY, DG; FS for DHE/ECDHE only |
| Threat model | Dolev-Yao; MITM; LT key compromise; cross-version downgrade |
| Modes | Full handshake, session-ID resumption, renegotiation; optional tickets (RFC 5077) |
| Primitives | AES-CBC, AES-GCM (optional), RC4, HMAC-SHA1/256, RSA PKCS#1 v1.5 KE, ECDHE/DHE |
| Proof | Informal (§F); no formal reduction |

## Findings

### F-001 — Static RSA key exchange: no FS + PKCS#1 v1.5 oracle class
- **Severity:** Critical
- **Pattern IDs:** F1, C15
- **Location:** §7.4.7.1 EncryptedPreMasterSecret; §8.1.1
- **Description:** PMS encrypted under server LT RSA with PKCS#1 v1.5. LT compromise decrypts all past RSA sessions; padding-oracle attacks recover PMS.
- **Attacker scenario:** Harvest TLS-RSA; later steal key or run ROBOT-class probes → session decrypt.
- **Affected goals:** FS, KS, IND
- **References:** Bleichenbacher 1998; ROBOT 2017; RFC 5246 §7.4.7.1
- **Fix:** Disable TLS_RSA_* KE; prefer ECDHE + AEAD; migrate to TLS 1.3.

### F-002 — CBC MAC-then-encrypt (BEAST/Lucky13 class)
- **Severity:** Critical
- **Pattern IDs:** C2, C3, I3
- **Location:** §6.2.3.2 GenericBlockCipher
- **Description:** MtE CBC remains mandatory-compatible (e.g. TLS_RSA_WITH_AES_128_CBC_SHA). Explicit IVs fix BEAST’s IV prediction vs TLS 1.0, but Lucky13-class padding/MAC timing and design remain.
- **Attacker scenario:** Chosen-boundary / timing oracles recover plaintext under CBC+HMAC suites.
- **Affected goals:** IND, EA, INT
- **References:** Lucky13 (CVE-2013-0169); RFC 5246 §6.2.3.2; RFC 7366 EtM
- **Fix:** Prefer AEAD suites only; disable CBC.

### F-003 — RC4 permitted
- **Severity:** Critical
- **Pattern IDs:** C6, N7
- **Location:** Appendix A.5 (e.g. TLS_RSA_WITH_RC4_128_SHA)
- **Description:** RC4 still a valid suite in the base RFC; biases enable plaintext recovery.
- **Attacker scenario:** RC4 NOMORE-class cookie recovery.
- **Affected goals:** IND, KS, DG
- **References:** RFC 7465; AlFardan et al.
- **Fix:** Never offer RC4 (RFC 7465).

### F-004 — Cipher/group/version negotiation strip (FREAK/Logjam class)
- **Severity:** Critical
- **Pattern IDs:** N1, N2, N3, R3, R4, R5
- **Location:** §7.4.1.2 ClientHello; §7.4.1.3 ServerHello; Appendix E
- **Description:** Offer lists cleartext; MITM can strip strong suites/groups. Finished authenticates the transcript both sides observed after strip. Version rollback to older TLS/SSL possible when peers allow multi-version.
- **Attacker scenario:** Force export/DHE-small/legacy suites; Logjam/FREAK-class breaks.
- **Affected goals:** DG, KS, BIND
- **References:** FREAK; Logjam; RFC 5246 Appendix E
- **Fix:** TLS 1.3 negotiation model; disable export/legacy; pin min version.

### F-005 — Static DH / ECDH cipher suites lack FS
- **Severity:** High
- **Pattern IDs:** F1, F2
- **Location:** DH_RSA, ECDH_RSA, ECDH_ECDSA suites
- **Description:** Fixed DH parameters from cert → no per-session ephemeral FS.
- **Attacker scenario:** Compromise static DH private key → decrypt historical sessions.
- **Affected goals:** FS
- **References:** RFC 5246 §7.4.3
- **Fix:** Use only ECDHE/DHE suites.

### F-006 — Renegotiation without prior-session binder (splice class)
- **Severity:** High
- **Pattern IDs:** I7, A5
- **Location:** §7.4.1.1 HelloRequest; renegotiation
- **Description:** Base RFC 5246 renegotiation does not bind the new handshake to the prior authenticated session (fixed later by RFC 5746 `renegotiation_info`). Without that extension, MITM can splice handshakes.
- **Attacker scenario:** Classic renegotiation MITM (CVE-2009-3555) when RFC 5746 not enforced.
- **Affected goals:** BIND, KA, MA
- **References:** CVE-2009-3555; RFC 5746
- **Fix:** Require RFC 5746; prefer TLS 1.3 (no renegotiation).

### F-007 — Session resumption reuses master_secret; weak ticket binding
- **Severity:** High
- **Pattern IDs:** F8, R8
- **Location:** §7.3 abbreviated handshake; tickets via RFC 5077
- **Description:** Resumption reuses MS without fresh KE contribution. Tickets may omit full identity/client-auth/ALPN context at issue; forgeability depends on ticket sealing.
- **Attacker scenario:** Steal MS or ticket sealing key → impersonate/resume; no FS for pure-PSK resume.
- **Affected goals:** FS, BIND, REPLAY
- **References:** RFC 5246 §7.3; RFC 5077
- **Fix:** TLS 1.3 resumption binders + optional PSK-DHE; bind full issue-time auth context.

### F-008 — Anonymous ECDH/DH suites
- **Severity:** High
- **Pattern IDs:** A1
- **Location:** TLS_DH_anon_*, TLS_ECDH_anon_*
- **Description:** No certificate authentication → MITM if selected.
- **Attacker scenario:** Active MITM on anon suites.
- **Affected goals:** KA, MA
- **References:** RFC 5246 suite list
- **Fix:** Disable anonymous suites.

### F-009 — Triple Handshake / channel-binding gaps
- **Severity:** High
- **Pattern IDs:** A3, A5, R8
- **Location:** Exporters (RFC 5705); resumption + renegotiation composition
- **Description:** Without full handshake transcript binding through client auth into exporters/resumption, channel binders can be reused across sessions (Triple Handshake class).
- **Attacker scenario:** Synchronize MS across two sessions; present same binder to different peers.
- **Affected goals:** BIND, UKS, KA
- **References:** Bhargavan et al., Triple Handshakes (2014)
- **Fix:** TLS 1.3 exporters; include full auth in session hash (RFC 7627 extended_master_secret).

### F-010 — Optional compression (CRIME)
- **Severity:** Medium
- **Pattern IDs:** C8
- **Location:** §6.2.2 CompressionMethod
- **Description:** Compression before encryption still negotiable.
- **Attacker scenario:** CRIME-class secret recovery via length.
- **Affected goals:** IND
- **References:** CRIME; RFC 3749
- **Fix:** Offer only null compression.

### F-011 — HMAC-SHA-1 suites and legacy hash in PRF options
- **Severity:** Medium
- **Pattern IDs:** N7
- **Location:** Cipher suites with SHA; §5 PRF
- **Description:** SHA-1 still used as MAC in many suites. HMAC-SHA-1 as MAC is Low interop smell per §2.8 if only MAC; elevates when collision-sensitive transcript uses SHA-1 alone in older profiles.
- **Attacker scenario:** Legacy compliance / future cryptanalysis margin loss.
- **Affected goals:** MA (margin)
- **References:** RFC 5246; NIST SP 800-131A
- **Fix:** SHA-256+ AEAD suites only.

### F-012 — No mandatory rekey / long-lived session keys
- **Severity:** Medium
- **Pattern IDs:** RD6, RD7
- **Location:** Record layer sequence; no KeyUpdate
- **Description:** Single traffic-key epoch for session lifetime; seq space large but no protocol rekey.
- **Attacker scenario:** Long-lived connections increase exposure window after key compromise (not PCS).
- **Affected goals:** FS (session span)
- **References:** Compare TLS 1.3 KeyUpdate
- **Fix:** Limit session lifetime; use TLS 1.3 KeyUpdate.

### F-013 — Client auth optional / strip of CertificateRequest
- **Severity:** Low
- **Pattern IDs:** A1
- **Location:** CertificateRequest optional
- **Description:** Unilateral server auth is intentional for web PKI; mutual auth only if CertificateRequest used and completed. If CR can be stripped when mutual auth is required by app, MITM may prevent client auth — depends on app policy (Finished still binds whether CR occurred).
- **Attacker scenario:** Policy mismatch: app assumes client cert but none negotiated.
- **Affected goals:** KA (mutual)
- **References:** §7.4.4
- **Fix:** App-layer fail-closed if client auth required.

### F-014 — No HNDL
- **Severity:** Info
- **Pattern IDs:** F6
- **Location:** All suites classical
- **Description:** Unclaimed HNDL — Info.
- **Attacker scenario:** Harvest-now decrypt-later.
- **Affected goals:** HNDL (unclaimed)
- **References:** —
- **Fix:** TLS 1.3 hybrid KE drafts if needed.

## Coverage Matrix

| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| KS | Partial | High | MITM + LT | Breaks under RSA/CBC/RC4 paths |
| IND | Partial | High | Active | AEAD OK; CBC/RC4 not |
| INT | Partial | High | Active | AEAD OK; CBC MtE not |
| EA | Partial | High | Active | Same |
| MA | Yes | High | Active | Finished |
| KA | Partial | High | MITM | Server cert; anon suites |
| FS | Partial | High | LT compromise | ECDHE/DHE only |
| PCS | N/A | — | — | Not claimed |
| FUT | N/A | — | — | Not claimed |
| HNDL | N/A | — | — | Unclaimed |
| DEN | N/A | — | — | Not claimed |
| ANO | N/A | — | — | Not claimed |
| REPLAY | Partial | High | Network | seq; resumption |
| DG | No | High | MITM | F-004 |
| KCI | Partial | Medium | LT | Static KE modes |
| UKS | Partial | Medium | Peer | Name binding external + Triple HS |
| BIND | Partial | Medium | MITM | EMS/RFC5746 needed |
| FR | Yes | High | Network | randoms |
| classical-param-strength | Partial | High | — | Depends on suite |

## Catalog Checklist (highlights)

| ID | Result | Reason |
|----|--------|--------|
| A1 | Yes | anon suites; optional client auth |
| A3,A5 | Yes | Triple HS / renegotiation without binders |
| C2,C3,C6,C8,C15 | Yes | CBC MtE, RC4, compression, PKCS#1 v1.5 |
| F1,F2,F8 | Yes | Static RSA/DH; resumption |
| I7 | Yes | Renegotiation splice without RFC 5746 |
| N1–N3,R3–R5 | Yes | Negotiation |
| R7* | N/A | No 0-RTT |
| K11 | No | Finished confirms |
| PQ* | N/A | No PQ |
| Other §3 | No/N/A | — |
