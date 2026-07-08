# Protocol Review: TLS 1.2 — RFC 5246

**Scope:** protocol logic only
**Source:** flaw-examples/tls12_rfc5246.txt (RFC 5246, August 2008)

---

## Summary

Findings: 4 Critical, 5 High, 3 Medium, 3 Low, 3 Info
Verdict: FAIL

TLS 1.2 improves over TLS 1.1 (explicit IVs, flexible PRF, SHA-256 default) but retains the structural flaws of the TLS 1.2 handshake family: CBC ciphers susceptible to BEAST/Lucky13, RC4 permitted with known biases, RSA-PKCS#1 v1.5 Bleichenbacher oracle, no forward secrecy for static key exchanges, and cipher-suite negotiation vulnerable to active downgrade. These are not implementation bugs — they are protocol-design deficiencies that TLS 1.3 addressed structurally.

---

## Attack-Pattern Checklist Results

### Authentication / Identity

| ID | Result | Reasoning |
|----|--------|-----------|
| A1 | **YES** | DH_anon and ECDH_anon cipher suites allow unauthenticated handshake — MITM feasible. |
| A2 | NO | Finished message binds key to negotiated cipher suite and transcript; UKS not a structural risk. |
| A3 | NO | No channel IDs in TLS 1.2. |
| A4 | NO | Static key compromise does not enable KCI of active sessions ( Finished binds peer ). |
| A5 | NO | Finished / CertificateVerify bind identities. |
| A6 | NO | Finished uses distinct `finished_label` ("client finished" vs "server finished"). |
| A7 | NO | KDF uses distinct labels ("master secret", "key expansion"). |
| A8 | N/A | TOFU not a TLS 1.2 concept. |
| A9 | NO | Master secret is derived via PRF, not used directly. |

### Replay / Ordering / Rollback

| ID | Result | Reasoning |
|----|--------|-----------|
| R1 | NO | Finished includes transcript hash; replay across sessions detectable. |
| R2 | NO | DH contributions are fresh per handshake. |
| R3 | **YES** | Server selects `server_version` as lower of client's and its own; client commits to ClientHello version before server response; no downgrade countermeasure beyond version number (cf. Appendix E / §F.1.2). |
| R4 | **YES** | ClientHello cipher list sent in the clear; attacker can strip preferred suites before ServerHello; server's single `cipher_suite` is selected from the (attacker's-modified) list. No client-commitment mechanism. |
| R5 | **YES** | Same as R4 for EC groups/curves negotiated via extensions; attacker can modify group preference. |
| R6 | NO | No ratchet step in TLS 1.2. |
| R7 | N/A | TLS 1.2 has no 0-RTT. |
| R7b | N/A | TLS 1.2 has no 0-RTT. |
| R8 | **YES** | Session resumption reuses master_secret; no fresh contribution from either party. Tickets carry session ID but no fresh client-server handshake material. |
| R9 | NO | Sequence numbers prevent stale replays within a session. |

### Key Derivation

| ID | Result | Reasoning |
|----|--------|-----------|
| K1 | NO | Labels are domain-separated: "master secret", "key expansion", "finished". |
| K2 | NO | Master secret derivation includes client_random + server_random as transcript context. |
| K4 | NO | HKDF salt is master_secret per session. |
| K5 | NO | No passwords in TLS 1.2 key exchange. |
| K6 | **YES** | `key_block = PRF(master_secret, "key expansion", server_random + client_random)` produces client_write_MAC_key, server_write_MAC_key, client_write_key, server_write_key in strict sequential order. No per-direction HKDF labels; keys differ by position, not by domain-separated label. Misbinding client→server keys is theoretically possible if implementers confuse the partition offset. |
| K7 | NO | Master secret is fed through PRF before producing keys. |
| K8 | N/A | First version using this PRF construction. |
| K9 | NO | No DRBG reuse in the spec. |
| K10 | NO | DH key exchange is contributory; RSA key exchange derives PMS from client-generated random. |
| K11 | NO | Finished message (`PRF(master_secret, finished_label, Hash(handshake_messages))`) provides key confirmation binding transcript + negotiated params to session keys. |

### Confidentiality / Encryption

| ID | Result | Reasoning |
|----|--------|-----------|
| C1 | NO | Per-record sequence numbers ensure nonce uniqueness for AEAD/stream ciphers. |
| C2 | **YES** | CBC cipher suites remain permitted (TLS_RSA_WITH_AES_128_CBC_SHA is mandatory). BEAST (CVE-2011-3389) exploits 1/n-1 record splitting in TLS < 1.1; TLS 1.2 with CBC retains the vulnerability if CBC + HMAC is used. Lucky13 (CVE-2013-0169) is a timing oracle on CBC padding/MAC verification. Section 6.2.3.2 describes MAC-then-encrypt (not Encrypt-then-MAC). The implementation note on constant-time processing (§6.2.3.2) is an implementation guidance, not a protocol-level fix. |
| C3 | INFO | Spec uses MAC-then-encrypt for block/stream; encrypt-then-MAC is not mandated. This is the root cause of Lucky13. |
| C4 | NO | No ECB mode defined for bulk encryption. |
| C5 | NO | CTR mode not defined as a standalone in TLS 1.2 cipher suites. |
| C6 | **YES** | RC4 stream cipher is permitted (e.g., TLS_RSA_WITH_RC4_128_SHA). RC4 has well-documented initial-keystream biases (Fluher, Mantin, Shamir 2001; Isobe et al. 2013, RC4 NOMORE 2015). Attackers can recover plaintext after ~2^26 encryptions in the BEAST/SLOTH threat model. RC4 is still listed as a valid cipher in Appendix A.5. |
| C7 | N/A | No KEM in TLS 1.2. |
| C8 | NO | Compression is optional (null by default); no in-protocol compression layer mandated. |
| C9 | INFO | Padding in CBC can leak length information up to 255 bytes; noted in spec. |
| C10 | NO | Client and server write keys are distinct. |
| C11 | NO | Nonce (sequence number + IV) is unique per record. |
| C12 | NO | No online oracle structure in TLS 1.2 record layer. |
| C13 | N/A | No SM4 in scope. |
| C14 | NO | Per-direction keys prevent multi-key decryption. |
| C15 | **YES** | RSA-PKCS#1 v1.5 encryption used for RSA key exchange (EncryptedPreMasterSecret). Bleichenbacher attack (1998) applies; spec acknowledges it (§7.4.7.1) and recommends randomized PMS on decryption failure, but does not mandate RSA-OAEP. The defense described (using random on padding error) is state-dependent and has had multiple subsequent refinements (ROBOT, 2017). |

### Forward / Future / Post-Compromise

| ID | Result | Reasoning |
|----|--------|-----------|
| F1 | **YES** | RSA key exchange: premaster secret is encrypted under the server's static RSA public key. If the server's long-term RSA key is compromised later, all past RSA-key-exchange sessions are decryptable. No ephemeral contribution. |
| F2 | **YES** | Fixed DH cipher suites (DH_DSS, DH_RSA, ECDH_ECDSA, ECDH_RSA) use DH parameters from the server's certificate. These are static across sessions. Compromising the long-term DH key exposes all prior sessions — no forward secrecy. |
| F3 | **YES** | TLS 1.2 has no per-message ratchet. After the handshake, the same derived keys are used for the entire session (up to rekey or close). No fresh DH contribution mid-session. |
| F4 | N/A | No symmetric ratchet defined. |
| F5 | NO | Long-term key (RSA cert / DH key) only encrypts the PMS; session keys are derived separately. |
| F6 | **YES** | No post-quantum or hybrid mechanism in TLS 1.2; all cipher suites are classical. |
| F7 | NO | No HSM specification in scope. |
| F8 | **YES** | Abbreviated handshake (session resumption) reuses the original master_secret directly; no fresh contribution from either party. |
| F9 | **YES** | No in-band self-healing mechanism (no ratchet, no tree update, no PQ refresh). Compromised long-term key or session key cannot be recovered without out-of-band revocation. |

### Negotiation / Downgrade

| ID | Result | Reasoning |
|----|--------|-----------|
| N1 | **YES** | ClientHello cipher_suites is an ordered list sent in plaintext before server commits to a selection. Active attacker can reorder/strip cipher suites. No commitment. |
| N2 | **YES** | Groups/curves negotiated via extensions (e.g.,elliptic_curves) not committed before server response. |
| N3 | **YES** | Client announces client_version; server selects server_version (lower of client's and its own). Client has committed before server response, but no mechanism prevents version rollback to TLS 1.0/SSL 3.0. Appendix E discusses version rollback; §F.1.2 describes the attack but the countermeasures are implementation-level, not protocol-enforced. |
| N4 | **YES** | Extensions follow the same pattern as cipher suites; not committed before ServerHello. |
| N5 | NO | Server returns a single cipher_suite; no ambiguity. |
| N6 | NO | ServerHello selects one suite; if ClientHello is modified in flight, server simply picks from the (attacker's) list. No hello-retry equivalent for negotiation mismatch. |
| N7 | NO | No formal deprecation path defined in the spec. |

---

## Findings

### F-001 — RSA Key Exchange Provides No Forward Secrecy
- **Severity:** Critical
- **Pattern IDs:** F1, C15
- **Location:** §7.4.7.1; §8.1.1
- **Description:** The RSA key exchange encrypts the 48-byte premaster secret using the server's static RSA public key from its certificate. The premaster secret is the only source of session key material. If the server's long-term RSA private key is later compromised, all past sessions using RSA key exchange are decryptable — there is no ephemeral contribution. The spec explicitly acknowledges Bleichenbacher's attack (§7.4.7.1) but mandates RSA-PKCS#1 v1.5 (not OAEP) for compatibility.
- **Attacker scenario:** State-level adversary or organized crime records today's TLS-RSA sessions. Five years later, server RSA key is exfiltrated. Adversary decrypts all historical RSA-key-exchange handshakes, recovering master secrets and all session data.
- **Affected goals:** FS, KS, IND
- **References:** Bleichenbacher (1998); ROBOT (2017, CVE-2017-6168); RFC 5246 §7.4.7.1, §8.1.1
- **Fix:** Use ECDHE or DHE key exchange; migrate to TLS 1.3 which eliminates static RSA key exchange entirely.

### F-002 — CBC Cipher Suites Vulnerable to BEAST and Lucky13
- **Severity:** Critical
- **Pattern IDs:** C2, R4
- **Location:** §6.2.3.2; §A.5 (cipher suite definitions)
- **Description:** TLS 1.2 mandates TLS_RSA_WITH_AES_128_CBC_SHA as the minimum mandatory cipher suite. CBC mode with MAC-then-encrypt is used. The BEAST attack (CVE-2011-3389) exploits the 1/n-1 record splitting weakness present when a block cipher operates in CBC mode with a known preceding block — the first ciphertext block of a record can be manipulated to cause predictable plaintext on the next record. Lucky13 (CVE-2013-0169) exploits timing differences in MAC-then-encrypt processing: padding errors are detected faster than authentication errors, creating a padding oracle. The spec acknowledges timing attack considerations in the implementation note to §6.2.3.2 but provides no protocol-level fix.
- **Attacker scenario:** Passive network adversary observes many TLS-CBC connections. With BEAST, they iteratively guess the first byte of each record's plaintext by controlling the final byte of the previous record. With Lucky13, the adversary sends crafted records and measures timing of bad_record_mac alerts to recover plaintext.
- **Affected goals:** IND, KS, EA
- **References:** BEAST (CVE-2011-3389); Lucky13 (CVE-2013-0169, AlFardan et al. 2013); RFC 5246 §6.2.3.2
- **Fix:** Use AES-GCM, AES-CCM, or ChaCha20-Poly1305 AEAD cipher suites. Migrate to TLS 1.3 which deprecates CBC entirely.

### F-003 — RC4 Stream Cipher Permitted with Known Biases
- **Severity:** Critical
- **Pattern IDs:** C6, RD4
- **Location:** §6.2.3.1; §A.5; enumerated in BulkCipherAlgorithm §6.1
- **Description:** RC4 is listed as a valid stream cipher (BulkCipherAlgorithm includes `rc4`). RC4's initial keystream bytes have well-documented statistical biases: the second byte is biased toward 0 with probability ~1/128 (Fluher-Mantin-Shamir 2001), and the first 256 bytes contain significant correlations that enable practical attacks (Isobe et al. 2013, RC4 NOMORE 2015). Attackers can recover passwords, cookies, and other sensitive data from TLS-RC4 connections after approximately 2^26 encryptions. The protocol provides no mechanism to limit RC4's use or to discard the initial keystream.
- **Attacker scenario:** Passive adversary collects many RC4-encrypted TLS records. After ~2^26 observed encryptions of the same plaintext structure (e.g., HTTP request with Authorization: Bearer token), statistical biases allow recovery of the token.
- **Affected goals:** IND, KS
- **References:** Fluher, Mantin, Shamir "On the Security of RC4 and TLS" (2001); Isobe et al. "Full Plaintext Recovery from RC4" (2013); RFC 7465 (RC4 must be disabled in TLS)
- **Fix:** Remove all RC4 cipher suites. Mandate AEAD cipher suites (AES-GCM, ChaCha20-Poly1305).

### F-004 — Bleichenbacher Oracle on RSA Key Exchange (C15)
- **Severity:** Critical
- **Pattern IDs:** C15
- **Location:** §7.4.7.1 (EncryptedPreMasterSecret)
- **Description:** RSAES-PKCS#1 v1.5 padding format used for EncryptedPreMasterSecret is vulnerable to Bleichenbacher's adaptive chosen-ciphertext attack. An attacker can distinguish correctly-formatted PKCS#1 v1.5 blocks from malformed ones (via alert timing, or bad_record_mac behavior). With enough probes (~2^20), the attacker recovers the PMS. The spec describes a defense of randomizing the PMS on padding error, but this is state-dependent and has been repeatedly shown to be insufficient (ROBOT 2017, multiple CVEs). The spec explicitly states "RSAES-OAEP encryption scheme defined in [PKCS1] is more secure against the Bleichenbacher attack. However, for maximal compatibility with earlier versions of TLS, this specification uses RSAES-PKCS1-v1_5."
- **Attacker scenario:** Network adversary performs TLS handshake with target server, modifying the EncryptedPreMasterSecret. By observing whether decryption succeeds (alert type), the attacker iteratively recovers the PMS. The defense (random PMS on error) reduces but does not eliminate the oracle.
- **Affected goals:** KS, EA
- **References:** Bleichenbacher (1998); ROBOT (CVE-2017-6168, 2017); RFC 5246 §7.4.7.1
- **Fix:** Use ECDHE key exchange. If RSA key exchange is required, implement RSA-OAEP (RFC 8017) or use a constant-time decapsulation with RSA Decryption Primitive (RSAVP) that never reveals padding validity.

### F-005 — Static DH Key Exchange Provides No Forward Secrecy
- **Severity:** High
- **Pattern IDs:** F2
- **Location:** §7.4.3 (ServerKeyExchange for DHE_*); §8.1.2; §A.5 (cipher suite definitions for fixed DH)
- **Description:** Fixed DH cipher suites (DH_DSS, DH_RSA, ECDH_ECDSA, ECDH_RSA) use Diffie-Hellman parameters embedded in the server's certificate. These parameters are static across sessions. The resulting shared secret Z becomes the premaster secret directly. If the long-term DH key is compromised, all historical sessions are decryptable — no ephemeral contribution was made.
- **Attacker scenario:** Adversary compromises server's static DH private key. All past sessions using that DH key are now fully decryptable.
- **Affected goals:** FS, KS
- **References:** RFC 5246 §8.1.2; [DH] cipher suite definitions
- **Fix:** Use ephemeral-ephemeral DH (DHE_RSA, DHE_DSS, ECDHE_RSA, ECDHE_ECDSA) which generate fresh per-session exponents. Migrate to TLS 1.3.

### F-006 — Cipher Suite Negotiation Vulnerable to Active Downgrade (N1, R4)
- **Severity:** High
- **Pattern IDs:** N1, R4
- **Location:** §7.4.1.2 (ClientHello cipher_suites); §7.4.1.3 (ServerHello cipher_suite)
- **Description:** The ClientHello contains an ordered list of cipher suites the client supports. The server selects one from this list and returns it in ServerHello. The ClientHello is sent in the clear before the server has committed to any choice. An active MITM can intercept the ClientHello, strip the client's preferred (strong) cipher suites, and forward only weak ones. The server responds with a cipher suite from the attacker's modified list. The Finished messages would still verify because both parties are using the same (attacker's-chosen) cipher suite. No mechanism commits the client to its cipher suite list before the server selects.
- **Attacker scenario:** MITM strips all AES-GCM and ChaCha20 suites from ClientHello, leaving only RC4 or 3DES. Server selects RC4. MITM now has a weak connection between client and server, with both believing they negotiated a secure channel.
- **Affected goals:** DG, KS
- **References:** RFC 5246 §7.4.1.2; Berg infra-attack class; POODLE (CVE-2014-3566)
- **Fix:** TLS 1.3 commits to cipher suite in ClientHello via `supported_versions` + `signature_algorithms` in transcript. For TLS 1.2, the only mitigation is to use a strong cipher suite preference list on both sides and to reject connections that downgrade below a security floor.

### F-007 — Version Negotiation Downgrade Window (N3, R3)
- **Severity:** High
- **Pattern IDs:** N3, R3
- **Location:** §7.2.2 (protocol_version alert); Appendix E; §F.1.2
- **Description:** Client sends ClientHello with `client_version` (the highest version the client supports). Server responds with `server_version` (lower of client's and its own). The client has committed to its version number before receiving ServerHello. An attacker can modify ClientHello to advertise TLS 1.0, and the server responds with TLS 1.0. The spec acknowledges this in Appendix E and §F.1.2 ("Detecting Attacks Against the Handshake Protocol"), but the only countermeasures are implementation checks (verifying the version number in Finished), not protocol-enforced commitments. No downgrade countermeasure comparable to TLS 1.3's `downgrade_random` bytes exists.
- **Attacker scenario:** MITM downgrades client to TLS 1.0, then exploits BEAST or POODLE (CVE-2014-3566) against the downgraded connection.
- **Affected goals:** DG, FS
- **References:** RFC 5246 Appendix E, §F.1.2; POODLE (CVE-2014-3566)
- **Fix:** Migrate to TLS 1.3, which includes explicit downgrade protection via `downgrade_random` in ServerHello.

### F-008 — Session Resumption Reuses Master Secret Without Fresh Contribution (F8, R8)
- **Severity:** High
- **Pattern IDs:** F8, R8
- **Location:** §7.3 (Figure 2 abbreviated handshake); §A.4.4
- **Description:** In abbreviated resumption, the client sends a ClientHello with the Session ID. The server responds with ServerHello using the same Session ID and the original cipher suite. Both parties send ChangeCipherSpec and Finished, but the master_secret is the original one — no fresh DH contribution or random from either side is mixed in. If the original master_secret is compromised, all resumed sessions are also compromised. There is no binding of the resumption to any fresh handshake material from the resumed connection.
- **Attacker scenario:** Adversary who has recorded a TLS session and later compromises its master_secret (e.g., via side channel or poor RNG) can impersonate both peers in all future resumed sessions, even if those sessions individually used strong cipher suites.
- **Affected goals:** FS, KS, REPLAY
- **References:** RFC 5246 §7.3; Triple Handshake (CVE-2009-3555)
- **Fix:** Use TLS 1.3 session resumption with PSK binder that includes a fresh handshake transcript, or implement PSK mode with external新鮮ness.

### F-009 — No In-Band Forward-Secrecy Recovery / Self-Healing (F9)
- **Severity:** High
- **Pattern IDs:** F9
- **Location:** §7 (handshake overview); §8 (cryptographic computations)
- **Description:** TLS 1.2 provides no mechanism to update session keys mid-session. After the handshake, the same master_secret and derived keys are used until connection close or explicit re-handshake. There is no ratchet, no tree update, no PQ component refresh. If a session key is compromised, subsequent traffic on that session is readable. If a long-term key is compromised, no in-band mechanism exists to heal the connection — only out-of-band revocation.
- **Attacker scenario:** Compromised endpoint or lateral movement enables an adversary to obtain the current session key. All subsequent traffic on that connection is readable until the connection closes. No automatic recovery.
- **Affected goals:** FS, PCS
- **References:** RFC 5246 §7 handshake overview
- **Fix:** Use TLS 1.3, which includes a key update mechanism. For TLS 1.2, implement application-layer re-handshake upon key expiry.

### F-010 — MAC-then-Encrypt Construction (Lucky13 Root Cause)
- **Severity:** Medium
- **Pattern IDs:** C3, C2
- **Location:** §6.2.3.1 (GenericStreamCipher); §6.2.3.2 (GenericBlockCipher)
- **Description:** The spec computes MAC over plaintext + sequence number + version + length, then concatenates MAC to plaintext and encrypts the combined structure (MAC-then-encrypt). This is vulnerable to padding oracle attacks when combined with CBC mode (Lucky13). The specification does not require encrypt-then-MAC. The only mitigation described is an implementation note in §6.2.3.2 recommending constant-time processing, which is not verifiable at the protocol level.
- **Attacker scenario:** (Same as Lucky13) Adversary sends malformed CBC records and measures timing of bad_record_mac responses to determine whether padding was valid, gradually recovering plaintext.
- **Affected goals:** IND, EA
- **References:** Lucky13 (AlFardan and Paterson, 2013); RFC 5246 §6.2.3.2
- **Fix:** Use AEAD (AES-GCM, ChaCha20-Poly1305) which does not require a separate MAC. Migrate to TLS 1.3 which removes all non-AEAD cipher suites.

### F-011 — Per-Direction Key Derivation Lacks Domain-Separated Labels (K6)
- **Severity:** Medium
- **Pattern IDs:** K6
- **Location:** §6.3 (Key Calculation)
- **Description:** `key_block = PRF(master_secret, "key expansion", server_random + client_random)` is partitioned sequentially: client_write_MAC_key | server_write_MAC_key | client_write_key | server_write_key | client_write_IV | server_write_IV. Keys are distinguished by position in the byte stream, not by domain-separated HKDF-style labels. While in practice both client and server know their own role and derive the correct slice, there is no cryptographic binding to a direction label that would detect a cross-direction key misuse if an implementation error caused client keys to be used server-side.
- **Attacker scenario:** Implementation bug causes client_write_key to be used for server_write operations. Because there is no direction label in the KDF, this misbinding is not detectable by the protocol.
- **Affected goals:** KS, BIND
- **References:** RFC 5246 §6.3; K6 in SKILL.md §3
- **Fix:** Use HKDF with explicit `info` labels per direction (e.g., "tls12 client write key" vs "tls12 server write key"), as TLS 1.3 does with its key schedule.

### F-012 — Groups and Extensions Not Committed Before ServerHello (N2, N4, N5)
- **Severity:** Medium
- **Pattern IDs:** N2, N4
- **Location:** §7.4.1.4 (Hello Extensions); §7.4.1.2 (ClientHello)
- **Description:** Elliptic curve groups (secp256r1, etc.) and other extensions (signature_algorithms, etc.) are negotiated in ClientHello but the server's choices are not committed before the client has sent its Finished. An active attacker can modify extension fields in ClientHello to force the server to use a weaker group. Finished messages will still verify because both parties are now operating on the attacker's-chosen parameter set. This is the group-equivalent of the cipher-suite downgrade (F-006).
- **Attacker scenario:** MITM modifies ClientHello to remove P-384 and only advertise P-256. Server selects P-256. Client and server both complete the handshake believing they used a secure group.
- **Affected goals:** DG, KS
- **References:** RFC 5246 §7.4.1.4; Logjam (CVE-2015-4000)
- **Fix:** Migrate to TLS 1.3, which includes group commitment in the key share extension mechanism.

### F-013 — Finished Message Does Not Include CertificateVerify (S5)
- **Severity:** Low
- **Pattern IDs:** S5
- **Location:** §7.4.9 (Finished); §7.4.8 (CertificateVerify)
- **Description:** The `CertificateVerify` message signs all handshake messages up to and including the client's key exchange, but the Finished message (sent after CertificateVerify) does not include CertificateVerify in its transcript. The Finished transcript for the server includes the client's Finished, but the client's Finished transcript does not include CertificateVerify. This means the client's signature on the transcript is not confirmed by the server's Finished — though the server must successfully verify the client's Finished which does depend on the client's key exchange message, which depends on the server's Certificate and the client's own key. This is not a severe issue but creates a theoretical gap where the server's Finished does not directly confirm the client certificate chain was properly signed.
- **Attacker scenario:** Theoretical: if a client's certificate is revoked between CertificateVerify and Finished, the server's Finished does not directly bind to the CertificateVerify signature.
- **Affected goals:** EA, BIND
- **References:** RFC 5246 §7.4.9; SKILL.md S5
- **Fix:** Include CertificateVerify in the Finished transcript (as TLS 1.3 does with its transcript hierarchy).

### F-014 — No Rekey Mechanism (RD6)
- **Severity:** Low
- **Pattern IDs:** RD6
- **Location:** §6.3; §7 (handshake overview)
- **Description:** TLS 1.2 has no mechanism to perform an in-band rekey operation. Session keys remain fixed for the entire session duration (up to 2^64 records or connection close). Long sessions are therefore at higher risk if session keys are compromised.
- **Attacker scenario:** Session keys compromised mid-session via memory disclosure. All subsequent records until connection close are readable.
- **Affected goals:** FS, KS
- **References:** RFC 5246 §6.3
- **Fix:** Use TLS 1.3 which includes a KeyUpdate handshake message.

### F-015 — Predictable Client Random via Low-Entropy Clock (RD1, RD2)
- **Severity:** Low
- **Pattern IDs:** RD1, RD2
- **Location:** §7.4.1.2 (ClientHello Random: gmt_unix_time + random_bytes)
- **Description:** The ClientHello.random structure includes a 32-bit `gmt_unix_time` (seconds since 1970) plus 28 bytes of "secure random." The timestamp reduces effective entropy of the client random by ~2^32 possibilities. While the 28 bytes of random_bytes add significant entropy, the timestamp portion can be predicted by an attacker who can observe the network traffic and infer the approximate time. This does not by itself break the protocol, but reduces the cost of brute-force search of the remaining 28-byte entropy.
- **Attacker scenario:** Passive adversary observes ClientHello, extracts the timestamp. Combined with knowledge of when the connection was initiated, this reduces the remaining search space for the 28 random bytes.
- **Affected goals:** KS
- **References:** RFC 5246 §7.4.1.2; Wagner 1996 on timestamp-based RNG weaknesses
- **Fix:** Use RFC 6979 deterministic nonces or ensure the full 32-byte random is drawn from a high-entropy CSPRNG without timestamp mixing.

### F-016 — Alerts Not Encrypted (M4)
- **Severity:** Info
- **Pattern IDs:** M4
- **Location:** §7.2 (Alert Protocol); §6.2.3
- **Description:** Alert messages (fatal and warning) are sent as TLSPlaintext records. They are protected by the current cipher state, meaning after the first ChangeCipherSpec they are encrypted. However, during the handshake, alerts before the first Finished are sent in the clear (or with null cipher). Error types like close_notify, bad_record_mac, and decryption_failed alerts can reveal information about connection state. In particular, distinguishing bad_record_mac from decompression_failure alerts during the handshake leaks information.
- **Attacker scenario:** Passive observer learns that a decryption failed at a specific point in the handshake, which can aid further attacks.
- **Affected goals:** IND
- **References:** RFC 5246 §7.2
- **Fix:** TLS 1.3 encrypts all alerts after the first Handshake context. For TLS 1.2, ensure null cipher is not used in production.

### F-017 — Sequence Number Wrapping Risk (RD6)
- **Severity:** Info
- **Pattern IDs:** RD6
- **Location:** §6.1 (Connection States: sequence number as uint64)
- **Description:** Sequence numbers are uint64. If they wrap (2^64 records), the connection must renegotiate. This is a theoretical ceiling; in practice, no TLS 1.2 connection approaches 2^64 records. However, for long-lived connections (years), this could be a real-world constraint.
- **Attacker scenario:** Not practically exploitable with current hardware and connection lifetimes.
- **Affected goals:** KS
- **References:** RFC 5246 §6.1
- **Fix:** Renegotiate before approaching 2^64 records (TLS 1.3 mandates rekey before 2^64).

### F-018 — No Formal Proof of Security
- **Severity:** Info
- **Pattern IDs:** N/A (design gap)
- **Location:** Appendix F (Security Analysis)
- **Description:** Appendix F provides informal security rationale but no reduction proof. The handshake's security properties (authentication, key secrecy, transcript integrity) are not proven against a formal adversary model in the RFC. Implementations have repeatedly deviated from the spec in subtle ways (e.g., handling of Bleichenbacher errors, CBC padding timing), leading to attacks.
- **Attacker scenario:** N/A — this is a gap in the specification's own self-security argument.
- **Affected goals:** All
- **References:** RFC 5246 Appendix F
- **Fix:** Consult formal verification tools (ProVerif, Tamarin) for TLS 1.2.

---

## Coverage Matrix

| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| KS (Key Secrecy) | Partial | High | Dolev-Yao MITM | Broken for RSA and static DH key exchange |
| IND (Indistinguishability) | Partial | High | Passive/Active | Broken by BEAST/Lucky13 on CBC; RC4 biases |
| FS (Forward Secrecy) | No | — | Long-term key compromise | Static RSA and static DH provide no FS |
| EA (Entity Authentication) | Partial | High | Dolev-Yao | Anon suites provide none; certificate auth is strong |
| MA (Message Authentication) | Yes | High | Dolev-Yao | HMAC-based MAC + Finished provide auth |
| KA (Key Agreement) | Yes | High | Dolev-Yao | ECDHE/DHE provide strong KA; RSA does not |
| PCS (Post-Compromise Security) | No | — | Future key compromise | No self-healing mechanism |
| DG (Downgrade Resistance) | No | — | Active MITM | Cipher suite, version, and group lists not committed |
| BIND (Identity Binding) | Yes | High | Active MITM | Finished + CertificateVerify bind identities to transcript |
| REPLAY (Replay Resistance) | Yes | High | Active replay | Finished and sequence numbers resist replays within session |

---

## References

- RFC 5246 — TLS 1.2 (Dierks & Rescorla, 2008)
- BEAST — CVE-2011-3389 (Duong & Rizzo, 2011)
- Lucky13 — AlFardan & Paterson (2013)
- RC4 NOMORE — Vanhoef & Piessens (2015)
- ROBOT — Bleichenbacher attack revival (2017)
- Logjam — CVE-2015-4000 (Durumeric et al., 2015)
- POODLE — CVE-2014-3566 (Moeller & Todorovic, 2014)
- Triple Handshake — CVE-2009-3555
- Bleichenbacher — "A Chosen Ciphertext Attack on RSA Optimal Asymmetric Encryption Padding" (1998)
