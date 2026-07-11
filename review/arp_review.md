# Protocol Review: EAP Key Management Framework (RFC 5247)

**Scope:** protocol logic only  
**Source:** `flaw-examples/arpitools.txt` (RFC 5247; **not** ARP — filename is historical)  
**Note:** README retains `arp_review.md` name for this document.

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

Findings: 1 Critical, 3 High, 3 Medium, 1 Low, 1 Info  
Verdict: **FAIL** (conditional PASS only under strong method + channel binding + modern AAA key wrap + lower-layer SAP freshness)

RFC 5247 is a key *framework*: security is conditional on EAP method properties, AAA transport (often RADIUS), channel binding, and lower-layer Secure Association Protocol (SAP). The document itself documents many of these gaps; the review scores residual design dependencies that break KS/KA/BIND when deployments use weak methods or skip bindings.

## Goals, Threat Model, Invariants, Primitives, Proof Strategy

| Artifact | Summary |
|----------|---------|
| Goals | MSK/EMSK export; peer↔authenticator session keys; media independence; RFC 4962-aligned key management |
| Roles | EAP peer, authenticator (often pass-through), backend EAP/AAA server |
| Modes | Full EAP auth; pass-through AAA; handoff / proactive key distribution; AAA bypass (fast handoff) |
| Threat model | Malicious authenticator, AAA on-path, peer compromise, handoff replication, missing channel bind |
| Proof | Extensive informal system analysis §5; not a cryptographic reduction |

## Findings

### F-001 — Security collapses under weak EAP methods (e.g. MD5-Challenge)
- **Severity:** Critical
- **Pattern IDs:** A1, P2, K3
- **Location:** §1.6.3 (pass-through; MD5-Challenge MTI in RFC 3748); method independence
- **Description:** Framework allows any EAP Type to pass through. RFC 3748 MTI MD5-Challenge provides no mutual auth, no dictionary resistance, no key derivation. When such a method is selected, exported MSK/TSK goals are unmet while the framework still “completes.”
- **Attacker scenario:** Force or configure EAP-MD5 (or other non-key-generating method) on WLAN-class media → offline password attack / MITM; no usable MSK.
- **Affected goals:** KA, KS, MA
- **References:** RFC 5247 §1.6.3; RFC 3748; RFC 4017 (WLAN method requirements)
- **Fix:** Policy: only methods meeting RFC 4017/4962 (mutual auth, key export, dictionary resistance); disable MD5-Challenge for network access.

### F-002 — Channel binding optional / incomplete → authenticator confusion
- **Severity:** High
- **Pattern IDs:** A5, A2, BIND
- **Location:** §1.4 channel bindings; §2.3 authenticator identification; §5.3–5.4
- **Description:** Peer may authenticate to a backend server while the serving authenticator identity is not cryptographically bound into the method. Without channel binding, a malicious/compromised AP can complete EAP toward the server while the peer believes a different network attachment.
- **Attacker scenario:** Evil twin / compromised authenticator relays EAP to real AAA; peer derives MSK believing correct SSID/BSSID; traffic keys installed with attacker-controlled AP.
- **Affected goals:** BIND, KA, UKS
- **References:** RFC 5247 §5.3.3, §2.3; RFC 6677 (later channel binding)
- **Fix:** Mandate channel binding of media parameters (SSID, BSSID, called-station-id) into method or EMSK-derived binder.

### F-003 — AAA key transport (RADIUS) integrity/confidentiality dependencies
- **Severity:** High
- **Pattern IDs:** K7, CP1, A7
- **Location:** §2; §3.8 key wrap; RADIUS [RFC3579]/[RFC2865]
- **Description:** MSK is transported authenticator←server over AAA. Classic RADIUS uses MD5-based authenticator/hide mechanisms — not modern AEAD key wrap. Compromise or oracle on AAA segment exposes MSK for all sessions that hop.
- **Attacker scenario:** On-path AAA attacker recovers MSK from Access-Accept attributes → decrypts or impersonates on the lower layer.
- **Affected goals:** KS, KA
- **References:** RFC 5247 §3.8; RFC 3579; RADIUS MD5 issues (historical)
- **Fix:** Diameter with TLS/IPsec or RADIUS/TLS (RFC 6614); AEAD key wrap; never MD5 hide for new deployments.

### F-004 — TSK freshness depends on lower-layer SAP (not EAP alone)
- **Severity:** High
- **Pattern IDs:** F8, R8, FR
- **Location:** §2.1 TSK; §3.1 Secure Association Protocol; §5.7 Key Freshness
- **Description:** Cached MSK reuse without a post-EAP handshake that proves freshness yields stale TSKs. Framework requires lower-layer SAP for freshness but cannot enforce it across all media.
- **Attacker scenario:** Replay or reuse of MSK-derived keys when SAP omitted (some PPP/legacy paths derive TSK directly from MSK).
- **Affected goals:** FS, FR, REPLAY
- **References:** RFC 5247 §5.7, §2.1; IEEE 802.11 4-way handshake contrast
- **Fix:** Always run SAP (4-way / equivalent) with nonces before traffic keys; never use raw MSK as TSK.

### F-005 — Handoff / AAA bypass key replication expands trust
- **Severity:** Medium
- **Pattern IDs:** F1, GP-class trust, R8
- **Location:** §4 Handoff; §4.3 AAA Bypass
- **Description:** Fast handoff may replicate keying material between authenticators or skip AAA authorization. Previous authenticator may learn keys for the new hop unless one-way derivation is used.
- **Attacker scenario:** Compromised AP1 obtains keys usable at AP2; or authorization skipped after AAA bypass.
- **Affected goals:** KS, FS, BIND (authorization)
- **References:** RFC 5247 §4.3.1–4.3.2
- **Fix:** One-way derive per-authenticator keys; re-authorize; limit handoff domain.

### F-006 — EMSK scope vs accidental export
- **Severity:** Medium
- **Pattern IDs:** K1, A7
- **Location:** §1.4 EMSK MUST NOT leave peer/server
- **Description:** Correct requirement, but framework complexity (TEK, IV, exports) creates footguns if implementations leak EMSK into AAA or lower layers.
- **Attacker scenario:** EMSK used as TSK or sent to authenticator → broader compromise / cross-purpose reuse.
- **Affected goals:** KS, BIND
- **References:** RFC 5247 §1.4, §1.6
- **Fix:** Hard isolation; domain-separated EMSK usages only via defined RFCs (e.g. ERP).

### F-007 — Ciphersuite negotiation outside EAP (downgrade at lower layer)
- **Severity:** Medium
- **Pattern IDs:** N1, R4
- **Location:** §1.6.4 Ciphersuite Independence
- **Description:** Data-protection ciphersuite negotiated in lower layer after EAP. If SAP does not authenticate the suite selection against the EAP-derived keys, downgrade is a lower-layer problem the framework cannot close alone.
- **Attacker scenario:** Force weak pairwise cipher if lower-layer negotiation unbound.
- **Affected goals:** DG, KS
- **References:** RFC 5247 §1.6.4; 802.11 4-way verifies RSN IE
- **Fix:** Bind negotiated suite into SAP (as 802.11 does); reject unbound media.

### F-008 — No HNDL / classical AAA and methods
- **Severity:** Low
- **Pattern IDs:** F6
- **Location:** Framework-wide
- **Description:** HNDL unclaimed; classical methods/AAA.
- **Attacker scenario:** Long-term harvest of transported MSK material.
- **Affected goals:** HNDL (unclaimed)
- **References:** —
- **Fix:** PQ-aware methods and AAA transports if required.

### F-009 — Informative system analysis is strong but non-normative elsewhere
- **Severity:** Info
- **Pattern IDs:** —
- **Location:** §5 Security Considerations
- **Description:** Excellent threat discussion; many mitigations are SHOULD/deployment guidance rather than hard interoperability MUST across all lower layers.
- **Attacker scenario:** Partial implementations omit SHOULD mitigations.
- **Affected goals:** —
- **References:** RFC 5247 §5
- **Fix:** Profile-specific RFCs with mandatory checklists (WLAN, PANA, etc.).

## Coverage Matrix

| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| KS | Partial | Medium | AAA + method | Conditional |
| IND | N/A | — | — | Lower layer |
| INT | Partial | Medium | Active | Method + SAP |
| EA | Partial | Medium | — | Lower layer |
| MA | Partial | Medium | MITM | Method-dependent |
| KA | Partial | Medium | Evil AP | Channel bind needed |
| FS | Partial | Medium | MSK cache | SAP-dependent |
| PCS | N/A | — | — | Not claimed |
| FUT | N/A | — | — | Not claimed |
| HNDL | N/A | — | — | Unclaimed |
| DEN | N/A | — | — | — |
| ANO | N/A | — | — | Identity often clear |
| REPLAY | Partial | Medium | Network | SAP counters |
| DG | Partial | Medium | Lower layer | Suite outside EAP |
| KCI | Partial | Low | Method-specific | — |
| UKS | Partial | Medium | Evil AP | Channel bind |
| BIND | Partial | Medium | Evil AP | F-002 |
| FR | Partial | Medium | Cache | F-004 |
| classical-param-strength | Partial | Medium | RADIUS MD5 | F-003 |

## Catalog Checklist (highlights)

| ID | Result | Reason |
|----|--------|--------|
| A1 | **Yes** | Weak methods / missing mutual auth |
| A2,A5 | **Yes** | Channel binding gaps |
| P2 | Yes | Password methods offline risk |
| F8,R8 | Yes | MSK cache without SAP |
| N1,R4 | Yes | Suite outside EAP |
| K1,K7 | Yes | Export/wrap domain issues |
| PQ* | N/A | No PQ |
| Other §3 | No/N/A | Framework scope |

## Conditional deployment profile (when FAIL becomes operationally acceptable)

1. EAP method: mutual auth + MSK/EMSK + dictionary resistance (RFC 4017-class)  
2. Channel binding enabled and verified  
3. AAA: confidential authenticated transport + modern key wrap (not RADIUS MD5 hide)  
4. Lower layer: SAP with nonces, suite binding, anti-replay  
5. Handoff: one-way per-AP keys + re-authorization  
