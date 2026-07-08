# Protocol Review: IPsec AH (RFC 2402)

**Scope:** protocol logic only
**Source:** RFC 2402 (IP Authentication Header), November 1998

## Summary
Findings: 0 Critical, 2 High, 3 Medium, 1 Low, 2 Info
Verdict: FAIL

## Goals, Threat Model, Invariants, Primitives, Proof Strategy
See associated analysis artifacts.

## Findings

### F-001 — No Confidentiality Protection (Payload Plaintext)
- **Severity:** High
- **Pattern IDs:** C1, M1, M2, M3
- **Location:** RFC 2402 §1, §2; entire protocol
- **Description:** AH provides ONLY integrity and data-origin authentication (ICV), with NO confidentiality/encryption. All upper-layer protocol data (TCP/UDP payloads, etc.) is transmitted in cleartext. The IP header is partially authenticated but mutable fields are zeroed rather than encrypted. This is explicitly by design: "AH is used to provide connectionless integrity and data origin authentication for IP datagrams... AH provides authentication for as much of the IP header as possible, as well as for upper level protocol data." ESP must be used separately to provide encryption.
- **Attacker scenario:** A passive network observer can read all application data in AH-protected packets. Traffic analysis reveals communication patterns, payload sizes, and timing. An on-path attacker can read all plaintext regardless of AH authentication.
- **Affected goals:** C (confidentiality), M1, M2, M3
- **References:** RFC 2402 §1; RFC 2401 (Security Architecture)
- **Fix:** Use ESP (RFC 2406) for confidentiality, or use AH+ESP in combination.

---

### F-002 — HMAC Truncation to 96 bits (C16)
- **Severity:** High
- **Pattern IDs:** C16
- **Location:** RFC 2402 §2.2, §2.6, §3.3.3.2.1; RFC 2403 (HMAC-MD5-96), RFC 2404 (HMAC-SHA-1-96)
- **Description:** The standard case for AH uses a 96-bit ICV (Integrity Check Value). The mandatory-to-implement algorithms are HMAC-MD5-96 and HMAC-SHA-1-96, both truncated to 96 bits. The spec states: "In the 'standard' case of a 96-bit authentication value... this length field will be '4'." This truncation is below the 128-bit minimum recommended for modern AEADs and introduces a birthday-bound weakness (~2^48 work to forge, rather than 2^128 for full HMAC output).
- **Attacker scenario:** A MITM can forge AH ICVs with approximately 2^48 work via birthday attack, allowing injection of packets with arbitrary content into an AH flow, as long as they can predict the mutable fields (which are zeroed anyway).
- **Affected goals:** INT (integrity), EA (external authentication)
- **References:** RFC 2402 §2.2, RFC 2403 §1, RFC 2404 §1; SKILL.md C16
- **Fix:** Require 128-bit minimum ICV strength, or use HMAC-SHA-256/384/512 with full output.

---

### F-003 — Unencrypted Metadata Leakage (SPI, Sequence Number, IP Header Fields)
- **Severity:** Medium
- **Pattern IDs:** M1, M2
- **Location:** RFC 2402 §2.4, §2.5, §3.1, §3.3.3
- **Description:** The SPI (32 bits), Sequence Number (32 bits), and portions of the IP header are transmitted in cleartext. The SPI uniquely identifies the Security Association and can reveal identity/communications partners to a passive observer. The Sequence Number, while authenticated via ICV, is visible as plaintext and can be used for traffic fingerprinting. Source and destination IP addresses are also unauthenticated (mutable fields are zeroed for ICV but visible on the wire).
- **Attacker scenario:** A passive observer can identify who is communicating with whom, track communication patterns, and correlate flows across time using the visible SPI and IP addresses. The sequence number reveals packet ordering and rate.
- **Affected goals:** ANO (anonymity), M1, M2
- **References:** RFC 2402 §2.4, §2.5, §3.3.3
- **Fix:** Encrypt AH (use ESP transport/tunnel mode with encryption, or consider future extensions to AH).

---

### F-004 — Mutable IP Header Fields Zeroed But Not Authenticated
- **Severity:** Medium
- **Pattern IDs:** R9, A5
- **Location:** RFC 2402 §3.3.3.1, §3.4.3
- **Description:** Mutable fields (TOS, TTL, Flags, Fragment Offset, Header Checksum) are zeroed before ICV computation and thus are NOT protected by the ICV. The sender sets these to predictable values, but an attacker can modify them. For example, TOS (Type of Service) is explicitly excluded from ICV coverage because "some routers are known to change the value." TTL changes "en-route as a normal course of processing." The receiver has no integrity protection for these fields.
- **Attacker scenario:** An on-path attacker can modify TTL, TOS, or other mutable fields without detection. This enables traffic analysis (TTL reveals hop count), QoS marking manipulation, or ICMP-based attacks (e.g., redirecting traffic by modifying routing fields).
- **Affected goals:** INT (integrity for mutable fields), R9
- **References:** RFC 2402 §3.3.3.1.1, §3.3.3.1.2
- **Fix:** Tunnel mode protects inner header; otherwise, mutable fields must be accepted as unverifiable.

---

### F-005 — Anti-Replay Optional and Sender-Assume Default (R7, R9)
- **Severity:** Medium
- **Pattern IDs:** R7, R9
- **Location:** RFC 2402 §2.5, §3.3.2, §3.4.3
- **Description:** Anti-replay is optional and receiver-controlled. The sender always transmits Sequence Number, but "the receiver need not act upon it." The sender "assumes anti-replay is enabled as a default, unless otherwise notified by the receiver." The receiver does NOT notify the sender of window size. If anti-replay is disabled, packets can be replayed indefinitely. With anti-replay enabled, the minimum window is only 32 packets.
- **Attacker scenario:** If the receiver disables anti-replay (or is expected to but didn't), an attacker can replay old captured packets. With a small window (32 minimum), an attacker who can intercept traffic can replay packets within the window.
- **Affected goals:** REPLAY, R7, R9
- **References:** RFC 2402 §2.5, §3.3.2, §3.4.3
- **Fix:** Make anti-replay mandatory, use larger windows, or bind sequence numbers to authenticated timestamps.

---

### F-006 — Weak Mandatory Algorithms (MD5, SHA-1)
- **Severity:** Low
- **Pattern IDs:** C15 (not Bleichenbacher but weak hash), primitive selection
- **Location:** RFC 2402 §5, RFC 2403, RFC 2404
- **Description:** The mandatory-to-implement authentication algorithms are HMAC-MD5-96 and HMAC-SHA-1-96. MD5 is known to have collision vulnerabilities (2004, 2005). SHA-1 has known weaknesses (SHAttered, 2017). Both use only 96-bit truncated output, compounding the weakness.
- **Attacker scenario:** Algorithm downgrade or cryptanalytic attacks on the hash function could undermine ICV integrity.
- **Affected goals:** INT
- **References:** RFC 2402 §5; SKILL.md §2.8 primitive selection
- **Fix:** Mandate HMAC-SHA-256 or stronger as minimum.

---

### F-007 — Manual Key Management Disables Anti-Replay
- **Severity:** Low
- **Pattern IDs:** R7
- **Location:** RFC 2402 §5, §3.3.2
- **Description:** When using manual key management, the anti-replay service is effectively disabled because "correct provision of the anti-replay service would require correct maintenance of the counter state at the sender, until the key is replaced, and there likely would be no automated recovery provision if counter overflow were imminent."
- **Attacker scenario:** Any manually-keyed SA has no replay protection.
- **Affected goals:** REPLAY, R7
- **References:** RFC 2402 §5
- **Fix:** Require automated key management (IKE) for anti-replay.

---

### F-008 — Sequence Number Authenticated but ICV Verification Order
- **Severity:** Info
- **Pattern IDs:** R9
- **Location:** RFC 2402 §3.4.3
- **Description:** The Sequence Number is in the ICV calculation, but the spec says duplicate detection should be the "first AH check applied to a packet." If a packet is rejected due to sequence number (replay), no ICV check occurs. However, this is a minor optimization issue, not a security flaw, because replays are rejected before ICV computation.
- **Attacker scenario:** Replay attacks processed within the window will still have valid ICVs (by definition, since they're captured from valid sessions).
- **Affected goals:** REPLAY
- **References:** RFC 2402 §3.4.3
- **Fix:** No action needed.

---

### F-009 — Fragmentation Before AH Processing
- **Severity:** Info
- **Pattern IDs:** M2
- **Location:** RFC 2402 §3.3.4, §3.4.1
- **Description:** AH is applied only to whole (non-fragmented) IP datagrams. If a packet is fragmented after AH processing, each fragment carries the AH header and ICV. Fragmented packets are reassembled before AH processing at the receiver. Packet sizes (and thus fragment patterns) are visible to observers.
- **Attacker scenario:** Traffic analysis via packet sizes and fragmentation patterns.
- **Affected goals:** M2
- **References:** RFC 2402 §3.3.4, §3.4.1
- **Fix:** Tunnel mode with inner fragmentation is unaffected.

---

## Coverage Matrix

| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| KS (Key secrecy) | N/A | N/A | N/A | AH does not establish keys |
| IND (Indistinguishability) | NO | High | Passive observer | All payload plaintext visible |
| INT (Integrity) | YES | Medium | MITM | Truncated HMAC weakens; mutable fields not protected |
| EA (External auth) | YES | Medium | MITM | ICV present but truncated |
| FS (Forward secrecy) | N/A | N/A | N/A | AH does not establish keys |
| PCS (Post-compromise) | N/A | N/A | N/A | AH does not establish keys |
| REPLAY | PARTIAL | Low | MITM/replay | Optional; manual keying disables it |
| ANO (Anonymity) | NO | High | Passive observer | SPI, IP addresses visible |

---

## Key Protocol Properties

| Property | Value |
|----------|-------|
| Authentication only | YES - no encryption |
| Integrity Check Value | 96-bit standard (truncated HMAC-MD5/SHA-1) |
| Anti-replay | Optional, sender-assumes-enabled |
| Key management | Manual or IKE |
| Transport mode | Protects L4 + partial IP header |
| Tunnel mode | Protects entire inner IP packet |

---

## References

- RFC 2402 (AH), RFC 2403 (HMAC-MD5-96), RFC 2404 (HMAC-SHA-1-96), RFC 2401 (Security Architecture), RFC 2406 (ESP)
- SKILL.md attack pattern catalog
