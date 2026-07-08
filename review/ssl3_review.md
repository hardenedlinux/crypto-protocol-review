# Protocol Review: SSL 3.0 (RFC 6101)

**Scope:** protocol logic only  
**Source:** RFC 6101 (https://www.rfc-editor.org/info/rfc6101)

## Summary
Findings: 3 Critical, 2 High, 2 Medium, 3 Low, 2 Info
Verdict: FAIL

## Goals, Threat Model, Invariants, Primitives, Proof Strategy
See goals.md, threat-model.md, invariants.md, primitives.md, proof-sketch.md.

## Findings

### F-001 — MAC-then-Encrypt (CBC) Enabling POODLE Attack
- **Severity:** Critical
- **Pattern IDs:** C2, C9
- **Location:** Section 5.2.3.1 (stream) and 5.2.3.2 (block CBC); GenericBlockCipher structure
- **Description:** SSL 3.0 uses MAC-then-encrypt for all protected records. The MAC is computed over plaintext, concatenated with the plaintext, and then the entire block is encrypted. For CBC mode (Section 5.2.3.2):
  ```
  block-ciphered struct {
      opaque content[SSLCompressed.length];
      opaque MAC[CipherSpec.hash_size];
      uint8 padding[GenericBlockCipher.padding_length];
      uint8 padding_length;
  } GenericBlockCipher;
  ```
  The MAC is generated per Section 5.2.3.1: `hash(MAC_write_secret + pad_2 + hash(MAC_write_secret + pad_1 + seq_num + SSLCompressed.type + SSLCompressed.length + SSLCompressed.fragment))`. Only then is everything encrypted as a single CBC chain. This construction allows an attacker to craft a valid padding byte at the end of the ciphertext chain and incrementally guess the last byte of any block. Since SSL 3.0 uses a 1-byte padding length field at the end of the CBC block (not an integer count of padding bytes like TLS), the attacker can reliably distinguish valid padding.
- **Attacker scenario:** A MITM intercepts a record, changes the last byte of a CBC block, and observes whether `bad_record_mac` is returned. By incrementing the byte value, the attacker identifies which causes valid padding. This leaks one byte of plaintext per attempt. The POODLE (Padding Oracle On Downgraded Legacy Encryption) attack allows recovery of a known plaintext byte with ~256 queries.
- **Affected goals:** IND (ciphertext indistinguishability), EA (encryption authenticity), KS (key secrecy)
- **References:** Bodo Moeller, "POODLE: Padding Oracle on Downgraded Legacy Encryption" (2014), CVE-2014-3566
- **Fix:** Use authenticated encryption (AES-GCM, ChaCha20-Poly1305) with encrypt-then-MAC, or at minimum HMAC-then-encrypt with a proper leakage-resistant construction (RFC 7366). Migrate to TLS 1.0+ which handles padding differently.

### F-002 — Version Rollback Attack Possible (N3)
- **Severity:** Critical
- **Pattern IDs:** N3, R3, R6
- **Location:** Sections 5.6.1.2/5.6.1.3 (ClientHello/ServerHello), F.1.2 (Appendix F Security Analysis), Appendix E (SSL 2.0 compatibility)
- **Description:** SSL 3.0 has no binding of the negotiated protocol version to the Finished message transcript. The ClientHello.client_version and ServerHello.server_version are not included in any transcript hash that is authenticated by Finished. While the RSA-based key exchange includes client_version in the EncryptedPreMasterSecret structure (Section 5.6.7.1), this only detects rollback after decryption—it does not prevent active MITM from forcing a version downgrade before key exchange completes. The Finished message (Section 5.6.9) computes MD5/SHA hashes over handshake_messages but does not incorporate the version field. The SSL 2.0 backward compatibility mode (Appendix E) explicitly allows version 3.0 clients to send version 2.0 ClientHello messages, providing a downgrade vector. The version rollback countermeasure in Section F.1.2 relies on PKCS#1 padding modifications that only work for RSA key exchange.
- **Attacker scenario:** A MITM observes a ClientHello advertising SSL 3.0, then modifies the version in the ClientHello to 2.0 before forwarding to server. If both parties support 2.0, they fall back. The attacker then performs a man-in-the-middle using weak 2.0 cryptography. Even if 2.0 is not used, the version negotiation itself is untrusted—the attacker can influence which version is selected without detection.
- **Affected goals:** DG (downgrade resistance), KA (key authentication), FS
- **References:** Section F.1.2 of RFC 6101 acknowledges rollback attacks; SSL 3.0 is inherently vulnerable to version downgrade
- **Fix:** Commit to version in ClientHello and verify in Finished (as TLS 1.3 does with supported_versions extension). Remove SSL 2.0 compatibility mode.

### F-003 — Cipher Suite List Not Committed (N1, R4)
- **Severity:** Critical
- **Pattern IDs:** N1, R4
- **Location:** Sections 5.6.1.1 (ClientHello), F.1.3 (Detecting Attacks)
- **Description:** The ClientHello.cipher_suites is a client preference list sent before any authentication. An attacker can intercept this list and remove strong cipher suites, causing the client and server to negotiate a weaker cipher. While the Finished message includes all handshake messages in its hash, an attacker who controls the wire can reorder or modify the cipher_suites list in flight. Since the Finished is computed after cipher selection, neither party can verify that the agreed-upon cipher was actually the first mutually acceptable choice in the client's list. The Finished only proves both parties have the same handshake transcript—it does not prove the server chose the client's first preference or any specific cipher suite.
- **Attacker scenario:** MITM strips 3DES/RC4 from the cipher list, forcing export-grade or NULL ciphers. The Finished messages still verify because the modified handshake is consistent on both sides.
- **Affected goals:** DG (downgrade resistance), IND
- **References:** Section F.1.3 acknowledges concern about cipher selection attacks but provides no cryptographic binding
- **Fix:** Include cipher_suite commitment in ClientHello (e.g., sign the full list) or derive Finished from server's actual choice with explicit binding.

### F-004 — No Transcript Hash Binding for Negotiation Parameters
- **Severity:** High
- **Pattern IDs:** K2, N3, R3, CP6
- **Location:** Sections 5.6.9 (Finished message), 6.1 (key computation)
- **Description:** The Finished message hashes handshake_messages using separate MD5 and SHA-1 hashes, concatenated. While this provides some binding of the handshake transcript, it does not bind the negotiated version, cipher suite, or compression method in a way that is verifiable by the other party before the Finished. The Finished includes `Sender.client` or `Sender.server` but not explicit negotiation parameters. The Finished message computation (Section 5.6.9) is:
  ```
  md5_hash: MD5(master_secret + pad2 + MD5(handshake_messages + Sender + master_secret + pad1))
  sha_hash: SHA(master_secret + pad2 + SHA(handshake_messages + Sender + master_secret + pad1))
  ```
  The `handshake_messages` includes ClientHello and ServerHello, but an attacker who removes cipher suites before they reach the server can cause the server to choose a different cipher than the client intended. The Finished still verifies because both sides processed the same modified hello messages. There is no separate negotiation integrity channel.
- **Attacker scenario:** Same as F-003—MITM trims cipher list, client and server compute different Finished but both accept because they have consistent modified transcripts.
- **Affected goals:** DG, BIND (binding of negotiation params to session)
- **References:** Compare to TLS 1.3 which uses HMAC-based transcript hash with explicit cipher suite binding
- **Fix:** Use a proper HKDF-based handshake hash (as TLS 1.3 does) that cryptographically binds all negotiated parameters.

### F-005 — Stream Cipher Nonce/Never-Used IV (C6)
- **Severity:** High
- **Pattern IDs:** C6, RD4
- **Location:** Section 5.2.3.1 (GenericStreamCipher), RC4 cipher suites
- **Description:** For stream ciphers (RC4), SSL 3.0 does not use an IV at all. Section 5.2.3.1 states: "For stream ciphers that do not use a synchronization vector (such as RC4), the stream cipher state from the end of one record is simply used on the subsequent packet." The key is established per-session but the stream cipher state (keystream position) is carried across records. This means if the same key is used for multiple records (which it is within a session), the keystream position must never overlap. Sequence numbers prevent record reordering but do not prevent keystream reuse if the implementation resets sequence numbers or if a session is resumed with the same keys.
- **Attacker scenario:** If a session resumes with the same master_secret (resumption uses existing master_secret per Section F.1.4), and RC4 state is not properly maintained across sessions, the same RC4 keystream could be reused. Additionally, if sequence numbers overflow (2^64 limit), keystream would overlap. The vulnerability is primarily theoretical for stream ciphers; the real danger is that weak keys (export ciphers) combined with stream cipher reuse can leak plaintext through known-prefix attacks.
- **Affected goals:** IND, KS
- **References:** Section 5.2.3.1; RC4 is known to have biases exploitable with repeated keystream
- **Fix:** Move to block ciphers with explicit IVs or AEAD. For stream ciphers, use unique per-record nonces combined with the key.

### F-006 — Weak Key Derivation Using MD5/SHA-1 Cascade (K1, K8, I1)
- **Severity:** Medium
- **Pattern IDs:** K1, K8, I1
- **Location:** Section 6.1 (master_secret), Section 6.2.2 (key_block)
- **Description:** SSL 3.0 derives the master_secret using a concatenation of MD5 and SHA-1 outputs:
  ```
  master_secret = MD5(pre_master_secret + SHA('A' + pre_master_secret + ClientHello.random + ServerHello.random)) +
                 MD5(pre_master_secret + SHA('BB' + pre_master_secret + ClientHello.random + ServerHello.random)) +
                 MD5(pre_master_secret + SHA('CCC' + pre_master_secret + ClientHello.random + ServerHello.random));
  ```
  This is not an HMAC-based KDF. It uses ad-hoc cascaded hash calls with simple letter suffixes for domain separation. While the dual hash (MD5+SHA) provides some fault tolerance, neither MD5 nor SHA-1 is considered secure for modern use (MD5 has known collisions, SHA-1 has reduced security). The KDF has no proof of PRF/PRG security. The key_block derivation uses the same pattern.
- **Attacker scenario:** An attacker with partial pre_master_secret knowledge cannot easily compute master_secret due to the cascade, but a break in MD5 or SHA-1 could compromise the KDF's output. The weak KDF also means that if pre_master_secret has low entropy, brute force is easier than with a proper PBKDF.
- **Affected goals:** KS, FS
- **References:** Section 6.1, 6.2.2; RFC 6151 (MD5 vulnerabilities in SSL 3.0 context)
- **Fix:** Use HKDF (RFC 5869) or at minimum HMAC-based KDF with SHA-256+.

### F-007 — Resumption Reuses Master Secret Without Fresh Contribution (F8, R8)
- **Severity:** Medium
- **Pattern IDs:** F8, R8
- **Location:** Section 5.5 (handshake overview), F.1.4 (resuming sessions)
- **Description:** Session resumption in SSL 3.0 reuses the original master_secret. The abbreviated handshake (Section 5.5) sends new ClientHello.random and ServerHello.random, which are hashed with the master_secret to derive new keys, but the master_secret itself is not refreshed. If the original master_secret is compromised (e.g., through side channel or weak key exchange), all resumed sessions are also compromised. The Finished message in resumption does bind the new nonces but the master_secret is not regenerated.
- **Attacker scenario:** Attacker compromises master_secret of one session (through export cipher or weak RSA key). All sessions resumed from that original session are also compromised. The new Finished in resumption only proves the party has the old master_secret, not fresh key material.
- **Affected goals:** FS, PCS (post-compromise security)
- **References:** Section F.1.4; note in F.1.4 that "24 hours" is suggested for session ID lifetimes to limit exposure
- **Fix:** Derive a new master_secret or at minimum a fresh master_secret derived from the original plus new DH/ephemeral contribution (full FS).

### F-008 — Anonymous Key Exchange Provides No MITM Resistance (A1)
- **Severity:** Low
- **Pattern IDs:** A1
- **Location:** Sections F.1.1.1 (anonymous key exchange), cipher suites SSL_DH_anon_*
- **Description:** SSL 3.0 supports anonymous DH key exchange where no party is authenticated. The cipher suite list includes SSL_DH_anon_EXPORT_WITH_RC4_40_MD5 and others. Anonymous sessions provide no protection against MITM—any attacker can establish a separate anonymous session with each party and relay messages.
- **Attacker scenario:** Standard MITM on anonymous DH—attacker sits between client and server, completes DH with each separately.
- **Affected goals:** KA (key authentication), EA
- **References:** Warning in Section F.1.1.1 explicitly acknowledges this
- **Fix:** Disallow anonymous cipher suites in favor of authenticated key exchange.

### F-009 — MD5/SHA-1 Hash Combination Does Not Prevent Collision Attacks on Finished (I1)
- **Severity:** Low
- **Pattern IDs:** I1, CP6
- **Location:** Section 5.6.9 (Finished), Section F.1.5 (MD5 and SHA)
- **Description:** The Finished message uses concatenated MD5 and SHA-1 hashes. The rationale in F.1.5 is that flaws in one algorithm won't break the overall protocol. However, this concatenation does not prevent collision-based attacks on the Finished verification. If an attacker can find a collision in MD5 or SHA-1, they could potentially create a different ClientHello that hashes to the same Finished input. The dual-hash is not a proper MAC construction (unlike HMAC). The use of `master_secret + pad1/pad2` as the HMAC-like key is ad-hoc and has not been proven secure under standard assumptions.
- **Attacker scenario:** If MD5 collision is found for two different ClientHellos, attacker could potentially substitute one ClientHello for another with same Finished hash (theoretically; practically difficult). More concerning: the Finished MAC can be forged if hash function is broken.
- **Affected goals:** INT, MA (message authenticity)
- **References:** Section F.1.5; MD5 known collisions since 2004 (Chosen Prefix)
- **Fix:** Replace with HMAC-SHA-256/384 or TLS 1.3's transcript hash using HMAC.

### F-010 — No Explicit Key Confirmation (K11)
- **Severity:** Low
- **Pattern IDs:** K11
- **Location:** Section 5.6.9 (Finished)
- **Description:** The Finished message serves as implicit key confirmation—it proves both parties have the same master_secret and handshake transcript. However, it does not explicitly confirm that the negotiated keys (client_write_key, server_write_key) match. An implementation error where keys are mismatched would not be caught until application data fails to decrypt. The Finished is not a dedicated key confirmation message with explicit confirmation semantics.
- **Attacker scenario:** Implementation bug where client and server derive different keys but Finished still passes (would require inconsistent transcript computation on each side).
- **Affected goals:** KA
- **References:** Compare to explicit key confirmation in TLS 1.3 Finished
- **Fix:** Add explicit key confirmation round or use Finished as strict confirmation.

### F-011 — Weak Export Cipher Key Derivation (K9, RD4)
- **Severity:** Info
- **Pattern IDs:** K9, RD4
- **Location:** Section 6.2.2.1 (export key generation example)
- **Description:** Export ciphers derive final keys using only MD5:
  ```
  final_client_write_key = MD5(client_write_key + ClientHello.random + ServerHello.random)
  ```
  This is a single round of MD5 with the key material and both random values. For export ciphers limited to 40-bit effective strength, this is arguably acceptable, but the key derivation itself is weak compared to the main key block derivation.
- **Attacker scenario:** Brute force of 40-bit key is already trivial; no additional cryptanalysis needed.
- **Affected goals:** KS
- **References:** Section 6.2.2.1
- **Fix:** Deprecate export ciphers entirely.

### F-012 — Alert Messages Not Encrypted in All Cases (M4)
- **Severity:** Info
- **Pattern IDs:** M4
- **Location:** Section 5.4 (Alert Protocol)
- **Description:** While the protocol specifies that alert messages are encrypted and compressed (Section 5.4), alerts before ChangeCipherSpec are sent in the clear. The close_notify alert is sent with the current cipher spec (after ChangeCipherSpec), but fatal alerts like bad_record_mac can be sent before the cipher is established. This means an attacker can observe alert types in cleartext, potentially aiding exploitation.
- **Attacker scenario:** Attacker learns that bad_record_mac occurred, which may indicate padding oracle activity, potentially aiding POODLE.
- **Affected goals:** M4
- **References:** Section 5.4
- **Fix:** Encrypt all alerts after initial handshake or use a separate alert channel with consistent encryption.

## Attack Pattern Catalog Coverage

| Pattern | ID | SSL 3.0 | Notes |
|---------|-----|---------|-------|
| CBC without MAC (MAC-then-encrypt) | C2 | YES | MAC computed before encryption, no authenticated tag |
| Stream cipher nonce reuse | C6 | YES | RC4 has no per-record nonce |
| Version rollback | N3 | YES | No binding of version to Finished |
| Cipher negotiation downgrade | N1, R4 | YES | Client cipher list modifiable in transit |
| MAC-then-encrypt padding oracle | C9 | YES | POODLE attack possible |
| Key derivation without proper KDF | K1, K8 | YES | Ad-hoc MD5/SHA cascade |
| No transcript binding | K2 | YES | Finished doesn't bind negotiated params |
| Resumption without fresh keys | F8, R8 | YES | Master secret reused |
| Forward secrecy absent | F1, F2 | YES | Static RSA/DH, no ephemeral FS by default |

## Coverage Matrix
| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| KS (Key Secrecy) | Partial | Medium | Passive + MITM | Master secret secure but derivable with broken hash |
| IND (Indistinguishability) | NO | High | CBC mode vulnerable to POODLE | MAC-then-encrypt enables oracle |
| INT (Integrity) | Partial | Medium | MAC present but unauthenticated encryption | malleability possible |
| EA (Encryption Authenticity) | NO | High | Padding oracle enables decryption | No AEAD |
| KA (Key Authentication) | Partial | Medium | Mutual auth optional; anonymous vulnerable | No KDF key confirmation |
| FS (Forward Secrecy) | NO | Low | Static RSA/DH; resumed sessions reuse master | Ephemeral DHE provides FS but not default |
| PCS (Post-Compromise Security) | NO | Low | No ratchet; compromise = total break | N/A |
| DG (Downgrade Resistance) | NO | High | Version/cipher not bound to Finished | Trivial downgrade |
| BIND (Transcript Binding) | Partial | Medium | Finished covers handshake but not explicit version | CP6 equivalent |
| REPLAY (Replay Resistance) | Partial | Medium | Sequence numbers prevent replay; resumption vulnerable | No anti-replay for 0-RTT equivalent |
