---
name: crypto-protocol-review
description: >
  Protocol-level security review of cryptographic communication protocols
  (TLS, Signal, Noise, custom handshakes, KEM exchanges, AEAD constructions,
  PQ migrations). Use for "review", "audit", "analyze", "find flaws in",
  "compare", or "model" the design of a crypto protocol. NEVER use for
  implementation review (constant-time, side channels, RNG internals, memory
  zeroing, fuzzing, library CVEs).
---

# Cryptographic Protocol Review Skill (Design-Level)

## ⚠️ Important Limitations

**This report is a reference, not a replacement for expert review.**

- AI-generated protocol analysis can miss critical vulnerabilities
- Cryptography engineering requires peer-reviewed expertise
- Formal verification (ProVerif, Tamarin) and implementation audit are required
- Side channels, constant-time code, and RNG internals are out of scope

**For production systems, engage certified cryptography engineers and conduct formal verification before deployment.**

*As JP Aumasson noted in [Murphy's Laws of Cryptography](https://www.aumasson.jp/murphy.html): "Any large enough system will include broken cryptography" and "New cryptography generates new attacks." Cryptographic protocol design is exceptionally difficult — failures are subtle, consequences are catastrophic, and automated analysis cannot catch all flaws.*

---

## 0. Scope

**In scope:** handshake flows, key derivation, primitive selection,
authentication/identity binding, FS/PCS/HNDL, replay/downgrade resistance,
state machines, version negotiation, KEM/PQ hybrid design.

**Out of scope (defer to code-audit skill):** constant-time code, side
channels, RNG internals, memory zeroing, library CVEs, and
configuration audits of named well-known implementations (e.g.
"check OpenSSL's default TLS 1.3 cipher list"). Design choices that
create or remove downgrade paths in a protocol's handshake,
including TLS, remain in scope (R3–R5).

---

## 1. Pipeline

Run in order. Produce each artifact before moving on.

1. `spec-extractor` → `protocol-model.json`
2. `security-goal-extractor` → `goals.md`
3. `threat-model-builder` → `threat-model.md`
4. `handshake-analyzer` → `handshake-flow.md`
5. `state-machine-auditor` → `state-machine.md`
6. `invariant-checker` → `invariants.md`
7. `naming-binding-auditor` → `naming.md`
8. `primitive-selector` → `primitives.md`
9. `proof-strategy-checker` → `proof-sketch.md`
10. `attack-pattern-checker` → `findings.md` (final report)

**Adjuncts (triggered by context):** upgrade-reviewer, protocol-comparator,
formal-model-translator. Escalate implementation findings (timing leaks on
key confirmation, non-constant-time comparison, RNG state) to code-audit skill.

A review is complete when every claim is mapped or marked unmet, every
message is traced, every catalog pattern is answered Yes/No/N/A, and every
severity has a concrete attacker scenario.

---

## 2. What to Check at Each Stage

### 2.1 Spec extraction
Extract into `protocol-model.json`:
- Roles, messages (direction + fields), primitives, keys, protocol state,
  out-of-band channels, negotiated parameters.

### 2.2 Security goals
Map explicit and implicit claims to: KS (Key Secrecy), IND (Indistinguishability), INT (Integrity),
EA (Encryption Authenticity), MA (Message Authenticity), KA (Key Authenticity),
FS (Forward Secrecy), PCS (Post-Compromise Security / self-healing), FUT (Future Secrecy / recovery),
DEN (Deniability), ANO (Anonymity — no dedicated §3 pattern; flag as Info gap if claimed),
REPLAY, DG (Downgrade), KCI (Key Compromise Impersonation), UKS (Unknown Key-Share), BIND, FR (Freshness).

### 2.3 Threat model
List in-scope adversaries: passive, Dolev-Yao, malicious peer/server/client,
long-term key compromise (drives FS evaluation), session/ephemeral key
compromise (drives PCS evaluation), compromised PKI, cross-protocol,
future/quantum/HNDL, global passive. Mark out-of-scope items. Flag claims
that are impossible under the chosen model.

### 2.4 Handshake analysis
For every message check:
- Freshness of nonces/ephemerals; for random nonces, limit messages per key well below the birthday bound; for counters, ensure monotonicity and no overflow (RD7).
- Identity authenticated to the peer's transcript (S5).
- Nothing committed before it is authenticated.
- Transcript covers all negotiation params (version, cipher, group, extensions).
- Transcript hash construction is unambiguous and collision/extension-resistant in context (CP5: equivalent-transcript or prefix-injection attacks must not yield the same handshake hash).
- Key confirmation present (Finished/MAC over transcript) (K11).
- Per-direction keys, not shared bidirectionally (K6).
  - Noise pattern matches the required auth/FS level (MF1); HPKE Auth/AuthPSK authentication properties reviewed separately (MF2).
- PSK resumption bound to prior session's identity and transcript (R8);
  cross-session reuse requires prior peer input.
- 0-RTT replayable within the recipient's anti-replay window by
  design — not for sensitive ops unless bound to fresh server input (R7, R7b).
- Session ticket / resumption token includes server-side freshness
  binding (timestamp or monotonic counter) and is rejected past
  its max_age; stale resumption must be gated by a server-side check.
- KEM: ML-KEM uses implicit rejection — decapsulation returns a
  pseudorandom shared secret for any ciphertext, so there is no rejection/failure path and
  no decapsulation-failure oracle. Explicit-rejection KEMs reveal valid vs
  invalid ciphertexts; prefer implicit rejection, or limit probing and
  ensure rejections are indistinguishable. Any public-key/ciphertext/length
  validation failure must abort without exposing which check failed (C7).
- Negotiated params are authenticated (N1–N5); on negotiation mismatch the
  protocol commits to a single ClientHello / uses a hello-retry equivalent
  before further progress (N6).
- TOFU first-use: after the first connection, no mechanism exists to
  detect or reject a MITM-forced key swap on subsequent connections (A8).
- Contributory agreement: both parties must contribute randomness to the
  shared secret (K10). A classical DH exchange or a mutual KEM exchange
  (each party encapsulates to an independent key) satisfies this; a
  single-encaps KEM (ML-KEM) on its own does not — combine it with a
  contributory component (see C7 for decapsulation-failure oracle risk).
- KEM public key is authenticated to the peer's identity / transcript
  (PQ2); the identity key or the authenticated transcript binds the KEM pk so MITM cannot
  swap it.
- Classic and PQ shares each contribute independently to the session
  key (PQ3); a break of one primitive must not collapse the other to
  the attacker's chosen value. Use a dual-PRF combiner; a contributory
  classical DH plus an independent KEM encapsulation satisfies
  this, as does any hybrid where each share is independently generated
  and the combiner is a dual PRF.
- PQ ciphertext is bound to the handshake transcript (PQ4); an
  attacker cannot substitute or replay a PQ ciphertext across
  sessions.
- Key-derivation labels are domain-separated across protocols and
  versions; non-uniform key material is extracted with salt before expansion.
  Same key material must not appear in two protocol contexts
  (K1, K3, A7).
- EC point validation: PV1–PV5 (see §3). For X25519/X448 rely on the
  all-zero shared-secret check (PV2). For finite-field DH: validate
  (p, q, g) first, then verify 1 < Y < p-1 and Y^q ≡ 1 mod p (q subgroup
  order); out-of-subgroup Y enables small-subgroup / weak-DLP share.
- If a PAKE mode is used: the stored verifier must not be a
  password-equivalent (P1), transcripts must not enable offline
  dictionary attack (P2), authentication attempts must be rate-limited
  (P3), session establishment may be gated by a client puzzle if
  DoS resistance is required (P3b), and session ticket / resumption
  token freshness is checked.

### 2.5 State machine
List states, triggers, guards, side effects. Verify transitions cover
error, rekey (RD6), and shutdown/alert paths (M4). Look for stuck states,
half-open sessions (peer disconnect not mapped to error/shutdown),
resumption confusion (R8), rollback (R6), stale-message replay (R9),
and missing or overflow-prone anti-replay state for 0-RTT and
resumption (R7, R7b); session ticket accepted without freshness check.

### 2.6 Invariants
Session-lifetime invariants — must hold beyond the handshake. Top
gotchas (cross-check §3 for full coverage):
- EC point validation: PV1–PV5.
- KEM failure indistinguishable from random (C7).
- 0-RTT anti-replay enforced; sensitive ops not accepted on 0-RTT
  (R7, R7b).
- Finished/key-confirmation binds negotiation params + identities to
  the session key (K11, R1, R3–R5).
- Resumption ticket age bound to the originating session; abbreviated
  resumption vs 0-RTT distinguished (R8).
- Rekey / session lifetime cap in place (RD6).
- F9: If PCS or FUT is claimed, recovery from session-key or long-term-key
  exposure is achievable either via in-band self-healing (ratchet
  step, MLS tree update, PQ-component refresh) or via out-of-band
  recovery (revocation + reissue).

### 2.7 Naming / binding
Trace every identity/name to the key that authenticates it. Flag:
- channel-bound but not identity-bound keys (A2/UKS),
- identity bound to unauthenticated channel (A4/KCI),
- channel ID reuse across users (A3),
- same key reused across protocol / version / purpose contexts (A7),
- challenge-response without direction tag — reflection possible (A6),
- identity misbinding: parties disagree on who shares the key (A5),
- group ID not bound to membership (GP1, GP3),
- long-term key used directly as session key (A9).

### 2.8 Primitive selection
Flag disallowed: MD5, SHA-1 (for collision-resistant hashing,
certificates, and signatures; HMAC-SHA-1 acceptable only in legacy
interop MAC contexts), DES/3DES, RC4, DSA (new signatures;
FIPS 186-5 allows only legacy verification), RSA-PKCS#1 v1.5 sigs,
RSA-PKCS#1 v1.5 encryption (C15), static RSA key transport / RSA key exchange without an ephemeral contribution (F1; RSA-KEM combined with an ephemeral DH contribution is acceptable), RSA < 2048, finite-field DH < 2048,
ECDH curves < 224, Dual_EC_DRBG, ANSI X9.31 PRNG, curves lacking standardized domain parameters or known to be weak
(e.g., anomalous curves, supersingular curves with low embedding degree
used outside pairing-friendly constructions, non-standard parameters).

Acceptable: AES-GCM, AES-GCM-SIV (RFC 8452; misuse-resistant), AES-CCM, ChaCha20-Poly1305,
SHA-2/3, BLAKE2 (RFC 7693), BLAKE3 (non-NIST; use where compliance permits), HMAC-SHA-256/384/512, HKDF,
X25519/X448 (ECDH), Ed25519/Ed448 (use Ed25519ctx or Ed448 with a context
string as a domain separator when cross-protocol or purpose separation is required,
per RFC 8032 §7.1), P-256/P-384/P-521, ECDSA with RFC 6979 nonces, RSA-PSS/OAEP,
ML-KEM (FIPS 203), ML-DSA (FIPS 204; lattice-based, formerly CRYSTALS-Dilithium;
use a distinct `ctx` string per protocol/purpose for domain separation),
SLH-DSA (FIPS 205; hash-based, formerly SPHINCS+; same `ctx` guidance).
Choose PQ parameter sets to match the security target (e.g., ML-KEM-512/768/1024, ML-DSA-44/65/87).

Flag for special review: regional algorithms — GOST R 34.10/34.11
(Russia), SM2/SM3/SM4/SM9 (China); confirm domain parameters, KDF
binding, and no cross-protocol reuse. Also check: version-negotiation
path, mandatory algorithms, fallback prohibition for deprecated
algorithms.

**Chinese national crypto (GM/T series) — extra scrutiny:**
- SM2: ECDSA-analog with different curve equation (y² = x³ + ax + b over
  F_p); verify: point-on-curve validation, cofactor clearing, nonce requirements.
  Signature scheme is NOT compatible with ECDSA — cross-protocol key reuse is
  NOT safe. SM2 signatures must bind the user identifier via Z_A (GM/T 0009 §5.1).
  Historical: no known forgeries against SM2 as used in TLS, but verify the
  KDF (SM3-based) is used, not a custom hash.
- SM3: Merkle–Damgård hash over 256-bit state; no known collision attacks
  published but younger than SHA-2. Use only where spec mandates (e.g.,
  GM/T 0024-2014 SSL). Do NOT substitute SHA-256 in non-SM contexts.
- SM4: 128-bit block cipher in CTR/OFB/CBC modes; equivalent security to
  AES-128 but no interop. Check: IV/nonce uniqueness per mode (same as C1/C6).
  AVOID mixed-mode compositions (e.g., SM4-CBC + HMAC-SM3 vs AES-GCM).
- SM9: Identity-based encryption; review master key escrowing, key isolation
  requirements, and whether the IBE scheme is IND-CCA2 under the q-type
  bilinear assumptions claimed in the GM/T profile (not plain BDH).

### 2.9 Proof strategy
If a proof is claimed in `proof-sketch.md`, verify the reduction target
(IND-CCA, EUF-CMA, KEM-IND-CCA, INT-CTXT, etc.) matches the goal and
threat model, the assumptions are listed explicitly, and any ideal-model
assumptions (ROM, ICM) are consistent with the chosen primitives. Flag
missing multi-instance / multi-key lemmas where multi-recipient settings
are claimed, honest-vs-malicious recipient mismatches in CPA→CCA
upgrades, and inconsistent modeling of KEM decapsulation failures
(implicit vs explicit rejection) relative to the adversary's oracle access. If the protocol claims a goal but provides no reduction, that
is itself a finding (not a pass).

### 2.10 Attack-pattern checker
Cross-reference the design against the catalog in §3. For each Yes, write a
finding with severity, location, attacker scenario, affected goals, real
references, fix suggestion. Do not invent CVEs.

**Severity rubric.**

| Severity | Definition |
|----------|------------|
| Critical | Fundamental break of core properties (EA/KA/KS/IND/FS) under the baseline DY model — catastrophic for any deployment |
| High | Break under realistic adversary (MITM, malicious peer) |
| Medium | Weakened property, bounded downgrade window, or a reasoning gap that could materially affect a goal |
| Low | Footgun / design smell / future-proofing |
| Info | Observation / clarification |

---

## 3. Attack Pattern Catalog

Check every pattern below. Mark Yes/No/N/A with one-line reasoning.

### Authentication / identity
- A1 — Missing mutual authentication → MITM.
- A2 — Unknown key-share (UKS): handshake authenticated but key shared with
  wrong peer.
- A3 — Channel ID reuse across users.
- A4 — Key compromise impersonation (KCI).
- A5 — Identity misbinding: parties disagree on who shares the key.
- A6 — Reflection / selfie attack.
- A7 — Cross-protocol or cross-purpose key reuse: same key material in multiple protocol contexts or for different cryptographic purposes (e.g., signing and key agreement).
- A8 — Trust-on-first-use without key-change detection: after the first
  connection, no mechanism exists to detect or reject a MITM-forced key
  swap on subsequent connections.
- A9 — Long-term key used directly as session key.

### Composition
- CP1 — Nested sessions or protocols without domain separation.
- CP2 — Two protocols sharing a PKI interact dangerously.
- CP3 — SM2/ECIES keys used with X9.62 parameter sets or vice versa
  (curve confusion; cf. CVE-2020-0601 class).
- CP4 — SM9 IBE master key escrowed but not isolated; key-encapsulation
  delegation without revocation check.
- CP5 — Transcript hash vulnerable to collision or prefix injection;
  encoding ambiguity enables equivalent-transcript attacks.

### Replay / ordering / rollback
- R1 — Replay of Finished/session-key message across sessions.
- R2 — Replay of key-exchange contribution.
- R3 — Downgrade via version negotiation.
- R4 — Downgrade via cipher negotiation.
- R5 — Downgrade via group negotiation.
- R6 — Rollback of ratchet step.
- R7 — 0-RTT replay without anti-replay (senders).
- R7b — 0-RTT recipient lacks anti-replay window (Bloom filter/PTS/Merkle) or accepts 0-RTT for sensitive ops.
- R8 — Resumption without context binding.
- R9 — Stale message replay (missing timestamp/nonce).

### Key derivation
- K1 — KDF without domain separation: same IKM, HKDF salt, or HKDF
  info/context reused across sub-keys, sessions, or protocol contexts without
  distinct labels, producing identical PRKs or OKMs.
- K2 — KDF without transcript context.
- K3 — Non-uniform or low-entropy IKM is used directly as a key, or
  HKDF-Extract/salt is omitted when IKM is not already a uniform random key
  (e.g., password, user-chosen PSK, low-entropy secret, weak-group DH output).
- K5 — Password stretched with only a fast hash (no PBKDF2/Argon2id/scrypt).
- K6 — Bidirectional keys derived without per-direction labels.
- K7 — Master secret used directly as application key.
- K8 — Cross-version KDF reuse.
- K9 — DRBG state reused across sessions without fresh entropy, or
  identical seed/personalization producing identical outputs.
- K10 — Non-contributory key agreement: one party forces the shared secret.
- K11 — Missing key confirmation, or confirmation MAC/tag is over a wrong or incomplete transcript.
- K12 — SM3-based KDF used without proper GM/T counter-mode structure; KDF
    instantiated as hash(master || label || counter) without HMAC or
    HMAC-based PRF construction. Verify against GM/T 0069-2018 if SM4-GCM
    is in scope.
- K13 — GM/T-specified MAC (e.g., SM4-CBC-MAC) used without domain
    separation between MAC and encryption keys.

### Confidentiality / encryption
- C1 — Nonce reuse under the same key (AEAD).
- C2 — CBC without MAC, or MAC-then-encrypt with CBC (padding-oracle / Vaudenay class).
- C3 — CBC + Encrypt-then-MAC misimplemented.
- C4 — ECB for structured/variable data.
- C5 — CTR with reused counter.
- C6 — Stream cipher with reused nonce.
- C7 — KEM decapsulation or ciphertext/public-key validation failure is distinguishable (explicit-rejection ⊥, error branches, timing). Prefer implicit-rejection KEMs; explicit-rejection KEMs must treat rejections indistinguishably. See §2.4.
- C8 — Plaintext compression before encryption (CRIME / BREACH class).
- C9 — Length leakage via padding.
- C10 — Same key used for both directions.
- C11 — Nonce not guaranteed unique but non-misuse-resistant AEAD used.
- C12 — Online decryption / partitioning oracle.
- C13 — SM4 modes (CTR/OFB/CBC) reuse IV; SM4-GCM/GMAC-style composition
  not verified against the applicable national spec (GM/T 0069-2018 for
  SM4-GCM; GM/T 0024-2014 covers SM4-CBC + HMAC-SM3, not GCM).
- C14 — AEAD lacks key commitment: ciphertext can be crafted that
  decrypts to valid plaintext under multiple keys in multi-recipient
  settings.
- C15 — RSA-PKCS#1 v1.5 encryption: Bleichenbacher padding oracle
  (1998). Under repeated probing, plaintext recovers (ROBOT, 2017 vs
  TLS 1.2 RSA key exchange). Use RSA-OAEP (RFC 8017).
- C16 — AEAD authentication tag truncated below 128 bits without
  justification (e.g., a 64-bit tag reduces forgery resistance to
  ~2^64 online queries). AES-GCM and ChaCha20-Poly1305 use 128-bit tags
  by design; AES-CCM permits shorter tags (e.g., TLS 1.3 CCM_8) but they
  must be justified by the threat model.

### Forward / future / post-compromise
- F1 — No ephemeral contribution to session key.
- F2 — Static DH claimed to provide FS (rotation protects future sessions but cannot heal already-established sessions).
- F3 — No ratchet / no fresh DH per message.
- F4 — Symmetric-only ratchet.
- F5 — Long-term key directly encrypts session traffic.
- F6 — No PQ / no hybrid for long-term confidentiality.
- F7 — HSM-stored key with no forward-mitigation plan.
- F8 — Resumption reuses old keys without fresh contribution.
- F9 — No PCS/FUT recovery mechanism: no in-band self-healing (ratchet,
  tree update, PQ-component refresh) or out-of-band recovery
  (revocation + reissue) after key exposure.

### Point validation / EC
- PV1 — EC point not verified on-curve → invalid-curve attack; attacker
  can choose weak curve parameters and forge signatures or derive bits
  (CVE-2020-0601).
- PV2 — Small-order or identity point accepted in DH → total break. For X25519/X448, verify the shared secret is not the all-zero value after DH.
- PV3 — Compressed point decoded without on-curve validation → invalid-point oracle.
- PV4 — Cofactor not cleared/checked in ECDH → small-subgroup / torsion-point attack; for X25519/X448 rely on the all-zero check (PV2).
- PV5 — ECDSA point not verified before signature verification → signature forgery.

### Signatures
- S1 — RSA-PKCS#1 v1.5 signature forgeries (Bleichenbacher 2006).
- S2 — ECDSA with biased, predictable, or non-uniform nonces (prefer RFC 6979 deterministic).
- S3 — Ed25519/Ed448 without explicit domain separator (use Ed25519ctx or Ed448 with a context string per RFC 8032 §7.1).
- S4 — Signature applied to raw message instead of a collision-resistant hash (mainly RSA/legacy schemes).
- S5 — Signature excludes part of the transcript.
- S6 — No domain separation between signature purposes.
- S7 — Rogue key / key substitution attack.
- S8 — SM2 signature used outside its mandated GM/T profile; Z_A/user-ID
  binding missing or ignored (GM/T 0009 §5.1).
- S9 — SM2 key format confused with X9.62/X9.63 EC key; parameter-set
    mismatch enables cross-protocol attack.
- S10 — ML-DSA / SLH-DSA signature context string (`ctx`) reused across protocol
  operations, or omitted where cross-protocol/purpose domain separation is required
  (FIPS 204 / FIPS 205).

### Negotiation / downgrade
- N1 — Cipher suite list not committed to handshake.
- N2 — Group/curve not committed.
- N3 — Version not committed.
- N4 — Extensions not committed.
- N5 — Multiple acceptable answers without tiebreak.
- N6 — No hello-retry-equivalent on mismatch.
- N7 — Algorithm agility without deprecation path.

### Randomness / nonce
- RD1 — Predictable session ID.
- RD2 — Time-based nonce.
- RD3 — Counter not monotonic across crashes.
- RD4 — Nonce predictable or reused under same key.
- RD5 — RNG seeded from low-entropy source.
- RD6 — No rekey / lifetime cap.
- RD7 — Nonce space too small.

### Post-quantum
- PQ1 — Hybrid combiner uses XOR or another non-dual-PRF construction; prefer
  a dual-PRF combiner so the output remains pseudorandom as long as at least one
  share is uniform and independent, preventing catastrophic failure if the other
  share is weak or compromised.
- PQ2 — KEM public key not authenticated.
- PQ3 — Classic and PQ shares not independently contributed.
- PQ4 — PQ ciphertext not bound to transcript.

### Group / multi-party
- GP1 — Sender key not bound to group membership.
- GP2 — Membership change does not update group key.
- GP3 — Members disagree on group epoch / partition.
- GP4 — Removed member retains decryption ability.
- GP5 — Group creator controls all keys (no contributory).

### Metadata / traffic analysis
- M1 — Unencrypted metadata leaks identity/membership/presence.
- M2 — Message size/timing leaks content.
- M3 — No padding or traffic-shaping; message size / timing leaks
  content or enables fingerprinting.
- M4 — Alerts not encrypted; distinguish close_notify from bad_record_mac.

### Modern frameworks (Noise / HPKE)
- MF1 — Noise pattern chosen does not match required authentication or
  forward-secrecy level (e.g., `Noise_N` provides no sender authentication;
  static-key patterns lose FS if the static key is compromised).
- MF2 — HPKE `Auth`/`AuthPSK` mode relies on the sender's static KEM
  key for authentication, but provides no explicit key-confirmation
  MAC over `secret`. If the application delegates AEAD sealing to a
  party other than the static-key holder, or if the static public key
  is not bound to the claimed identity, authentication is lost. Bind
  the static key to identity and add an explicit MAC under `secret`
  when the threat model requires it.

### PAKE
- P1 — Password verifier equivalent to password.
- P2 — Offline dictionary attack on transcripts.
- P3 — No rate limiting on authentication attempts.
- P3b — No client puzzle / proof-of-work; DoS-gating on session establishment is absent (P3b does not replace anti-replay — 0-RTT and resumption anti-replay are separate requirements, cf. R7/R7b/R8).

### Revocation / recovery
- REV1 — No key revocation mechanism.
- REV2 — Compromised device cannot be excluded.

### Encoding / wire format
- E1 — Ambiguous length fields or duplicate fields parsed inconsistently
  across implementations, enabling transcript manipulation.

### Deniability
- DEN1 — Non-repudiable signatures break deniability.
- DEN2 — Online vs offline deniability mismatch.

### Design smells
- I1 — Length-extension on SHA-2 (use HMAC or SHA-3).
- I2 — Asymmetric encrypt-and-sign without careful binding.
- I3 — Custom padding scheme where AEAD would have removed the
  oracle (Vaudenay 2002 padding-oracle class).
- I4 — Password used as direct key.
- I5 — No protocol versioning at all.
- I6 — Session bound to network location (IP/VPN) — breaks on mobility.

---

## 4. Output Format — `findings.md`

```markdown
# Protocol Review: <name> v<version>

**Scope:** protocol logic only
**Source:** <link/path>

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
Findings: N Critical, N High, N Medium, N Low, N Info
Verdict: PASS / PASS-WITH-FIXES / FAIL

## Goals, Threat Model, Invariants, Primitives, Proof Strategy
See goals.md, threat-model.md, invariants.md, primitives.md, proof-sketch.md.

## Findings

### F-001 — <title>
- **Severity:** Critical
- **Pattern IDs:** A1, K2
- **Location:** Step 4; `master_secret = SHA256(...)`
- **Description:** ...
- **Attacker scenario:** ...
- **Affected goals:** FS, KS
- **References:** CVE-XXXX-XXXX / paper
- **Fix:** ...

## Coverage Matrix
| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
```

---

## 5. Brief Protocol Notes

- **TLS 1.3** — downgrade protected by `supported_versions` + transcript + downgrade random; 0-RTT replayable by design. ECDHE requires the all-zero shared-secret check for X25519/X448. Standalone ML-KEM key agreement is OPTIONAL via draft-ietf-tls-mlkem; the ECDHE+ML-KEM hybrid is OPTIONAL via draft-ietf-tls-ecdhe-mlkem. Without a PQ key-agreement mechanism, long-term confidentiality is vulnerable to harvest-now/decrypt-later (HNDL) by a future quantum adversary. If HNDL resistance is a goal, a PQ mechanism (standalone or hybrid) is required.
- **X3DH → PQXDH** — PQXDH combines X25519 (4 DH outputs in the classic X3DH set: identity×SPK, ephemeral×IK, ephemeral×SPK, optional ephemeral×OPK) with ML-KEM-encapsulated shared secret via HKDF. The HKDF info label is a fixed, protocol-versioned string that MUST be domain-separated from X3DH; verify the exact label against the target spec. Both the X25519 and ML-KEM components must each contribute independently to the final secret — a MITM who strips the PQ key share can force classical-only X3DH (PQ3 gap; both components must be present and independently derived). Additionally: authenticate PQ public key under identity key (PQ2), bind PQ ciphertext to the handshake identity (PQ4).
- **OTRv3 / OTRv4** — Off-the-Record messaging protocols built for deniability and forward secrecy. OTRv3 uses an online AKE + Socialist Millionaire Protocol for authentication, and conceals public keys from network observers. OTRv4 adds offline/online handshakes and a double-ratchet-like messaging layer, but dropped public-key concealment; verify the handshake model and deniability claims against the target spec.
- **vault1317** — Signal-inspired protocol that adds ring-signature-based deniability and public-key/metadata concealment. Review ring-signature member binding, handshake identity hiding, and leakage through handshake timing/size.

---

## 6. References

**IETF / RFCs:**
- TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446
- HPKE: https://www.rfc-editor.org/rfc/rfc9180
- MLS: https://www.rfc-editor.org/rfc/rfc9420
- Ed25519: https://www.rfc-editor.org/rfc/rfc8032
- PQ/T Hybrid Terminology: https://www.rfc-editor.org/rfc/rfc9794
- ML-KEM for TLS 1.3 (draft): https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/
- ECDHE-ML-KEM hybrid for TLS 1.3 (draft): https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/

**Signal protocols:**
- X3DH: https://signal.org/docs/specifications/x3dh/
- PQXDH: https://signal.org/docs/specifications/pqxdh/

**OTR:**
- OTRv3: https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html
- OTRv4: https://github.com/otrv4/otrv4/blob/master/otrv4.md

**vault1317:**
- https://github.com/hardenedvault/vault1317 (paper: vault1317.pdf in repo)

**NIST standards (csrc.nist.gov):**
- FIPS 186-5 (ECDSA): https://csrc.nist.gov/pubs/fips/186-5/final
- FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
- FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- FIPS 205 (SLH-DSA): https://csrc.nist.gov/pubs/fips/205/final
- SP 800-56A Rev. 3 (key establishment): https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
- SP 800-56C Rev. 2 (KDF): https://csrc.nist.gov/pubs/sp/800/56/c/r2/final
- SP 800-131A Rev. 2 (algorithm transitions): https://csrc.nist.gov/pubs/sp/800/131/a/r2/final
- SP 800-227 (KEM recommendations): https://csrc.nist.gov/pubs/sp/800/227/final

**Chinese crypto (GM/T series — not freely online; cite by standard number):**
- GM/T 0009-2012 (SM2 digital signature algorithm)
- GM/T 0024-2014 (SSL/TLS protocol using SM2/SM3/SM4)
- GM/T 0069-2018 (SM4-GCM authenticated encryption)

**Analysis tools:**
- ProVerif: https://proverif.inria.fr/
- Tamarin: https://tamarin-prover.github.io/
- Verifpal: https://verifpal.com/

**Attacks:** Bleichenbacher, ROBOT, FREAK/Logjam, KRACK, Triple Handshake.
