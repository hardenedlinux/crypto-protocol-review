# Protocol Review: IPsec ESP (RFC 2406)

**Scope:** protocol logic only  
**Source:** `flaw-examples/ipsec_esp.txt` (RFC 2406)

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

Findings: 1 Critical, 3 High, 2 Medium, 1 Low, 0 Info  
Verdict: **FAIL**

ESP correctly prefers encrypt-then-MAC when both services are selected, but allows encryption with NULL authentication, legacy algorithms (DES-CBC MTI), and optional anti-replay — enabling bit-flipping and weak deployments.

## Goals, Threat Model, Invariants, Primitives, Proof Strategy

| Artifact | Summary |
|----------|---------|
| Goals | Optional confidentiality; optional auth/integrity; optional anti-replay (requires auth) |
| Constraint | At least one of conf or auth MUST be selected (§1, §5) — both may not be NULL simultaneously |
| Threat model | On-path active attacker; passive eavesdropper |
| Key mgmt | Manual keys or IKE (out of document) — FS depends on IKE/PFS |
| Proof | Informal |

## Findings

### F-001 — Encryption without authentication (NULL auth)
- **Severity:** Critical
- **Pattern IDs:** C2
- **Location:** §1; §2.7 Authentication Data optional; §5 (both MUST NOT be NULL, but conf-only allowed)
- **Description:** ESP may run with confidentiality and NULL authentication. Unauthenticated CBC (DES-CBC MTI) is malleable: bit flips in ciphertext produce predictable plaintext changes.
- **Attacker scenario:** MITM flips bits in Payload Data / Next Header / padding on conf-only SA; receiver accepts modified plaintext (Bellovin 1996 class).
- **Affected goals:** INT, EA, IND
- **References:** Bellovin, “Problem Areas for the IP Security Protocols” (1996); RFC 2406 §1, §5
- **Fix:** Mandate authentication whenever encryption is used; prefer AEAD (AES-GCM). Prohibit conf-only SAs.

### F-002 — Mandatory-to-implement DES-CBC
- **Severity:** High
- **Pattern IDs:** N7, C2
- **Location:** §5 Conformance; DES-CBC profile
- **Description:** DES-CBC is MTI: 56-bit key, 64-bit block (Sweet32-class issues for long-lived bulk).
- **Attacker scenario:** Brute-force DES or birthday collision on 64-bit blocks under high volume.
- **Affected goals:** KS, IND, classical-param-strength
- **References:** RFC 2405; Sweet32; NIST SP 800-131A
- **Fix:** AES-GCM/CCM or ChaCha20-Poly1305; drop DES.

### F-003 — Anti-replay optional at receiver
- **Severity:** High
- **Pattern IDs:** R9
- **Location:** §2.5 Sequence Number; §3.3.3; §3.4.3
- **Description:** Sequence numbers always sent, but receiver may disable anti-replay. Without window, replays succeed under valid ICV.
- **Attacker scenario:** Replay captured ESP packets when anti-replay off or window not shared across multi-homed receivers.
- **Affected goals:** REPLAY
- **References:** RFC 2406 §3.4.3
- **Fix:** Mandate anti-replay for unicast SAs; durable shared state for multi-endpoint.

### F-004 — FS not provided by ESP alone (static/manual keys)
- **Severity:** High
- **Pattern IDs:** F1, A9
- **Location:** Manual keying; SA keys as traffic keys
- **Description:** ESP consumes SA keys; manual or non-PFS IKE yields no FS. Long-term key material directly protects traffic.
- **Attacker scenario:** Record ESP; later obtain SA/LT key → decrypt history.
- **Affected goals:** FS, KS
- **References:** RFC 2401/2409 interaction
- **Fix:** IKE with mandatory PFS (ephemeral DH); short SA lifetimes.

### F-005 — NULL encryption with weak/NULL auth configurations
- **Severity:** Medium
- **Pattern IDs:** C2, A1
- **Location:** §1; NULL encrypt profiles
- **Description:** Spec forbids simultaneous NULL+NULL but allows NULL encrypt + weak MAC. Auth-only is intentional for some deployments but easy to misconfigure.
- **Attacker scenario:** Misconfiguration → cleartext plus forgeable packets if MAC weak/NULL.
- **Affected goals:** KS, INT
- **References:** RFC 2410; RFC 2406 §5
- **Fix:** Policy: require strong AEAD; config lint against weak pairs.

### F-006 — 96-bit ICV profiles common with ESP auth
- **Severity:** Medium
- **Pattern IDs:** C16
- **Location:** HMAC-MD5-96 / HMAC-SHA-1-96 usage with ESP
- **Description:** Truncated 96-bit tags (online forgery ~2^96) below modern 128-bit floor without strong justification.
- **Attacker scenario:** Large-scale online forgery attempts against ICV (costly but below 128-bit design target).
- **Affected goals:** INT, MA
- **References:** RFC 2403/2404; SKILL.md C16
- **Fix:** 128-bit+ tags or AEAD.

### F-007 — No HNDL / classical-only algorithms
- **Severity:** Low
- **Pattern IDs:** F6
- **Location:** Algorithm suite (1998-era)
- **Description:** HNDL unclaimed — Low/Info smell for long-term conf.
- **Attacker scenario:** Harvest-now decrypt-later.
- **Affected goals:** HNDL (unclaimed)
- **References:** —
- **Fix:** Modern IKEv2 + PQ hybrid if required.

## Coverage Matrix

| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| KS | Partial | High | Passive + key compromise | Depends on alg/keys |
| IND | No | High | Active | Conf-only malleability |
| INT | Partial | High | Active | Only if auth selected |
| EA | Partial | High | Active | EtM when both on |
| MA | Partial | High | Active | Optional |
| KA | N/A | — | — | IKE scope |
| FS | No | High | LT/SA key leak | Not in ESP |
| PCS | N/A | — | — | Not claimed |
| FUT | N/A | — | — | Not claimed |
| HNDL | N/A | — | — | Unclaimed |
| DEN | N/A | — | — | — |
| ANO | N/A | — | — | SPI/IP metadata clear |
| REPLAY | Partial | High | Network | Optional |
| DG | N/A | — | — | IKE negotiation |
| KCI | N/A | — | — | — |
| UKS | N/A | — | — | — |
| BIND | Partial | Medium | — | SPI/SA binding |
| FR | Partial | High | — | Seq when anti-replay on |
| classical-param-strength | No | High | — | DES MTI |

## Catalog Checklist (highlights)

| ID | Result | Reason |
|----|--------|--------|
| C2 | **Yes** | Conf-only / unauth CBC |
| C16 | Yes | 96-bit ICV profiles |
| F1 | Yes | Manual/static SA keys |
| R9 | Yes | Optional anti-replay |
| N7 | Yes | DES still MTI |
| A1 | Partial | Auth optional |
| Other §3 | No/N/A | — |
