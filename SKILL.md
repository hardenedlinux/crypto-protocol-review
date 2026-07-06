---
name: crypto-protocol-review
description: >
  Protocol-level security review of cryptographic communication protocols
  (TLS, Signal, Noise, custom handshakes, KEM exchanges, AEAD constructions,
  PQ migrations). Use for "review", "audit", "analyze", "find flaws in",
  "compare", or "model" the design of a crypto protocol. NEVER use for
  implementation review (constant-time, side channels, RNG internals, memory
  zeroing, fuzzing, library CVEs).
trigger:
  - "review this protocol"
  - "audit the handshake"
  - "find protocol-level flaws"
  - "analyze the crypto design"
  - "compare protocol X vs Y"
  - "review the PQ upgrade"
---

# Cryptographic Protocol Review Skill (Design-Level)

## 0. Scope

**In scope:** handshake flows, key derivation, primitive selection,
authentication/identity binding, FS/PCS/HNDL, replay/downgrade resistance,
state machines, version negotiation, KEM/PQ hybrid design.

**Out of scope (defer to code-audit skill):** constant-time code, side
channels, RNG internals, memory zeroing, library CVEs, TLS configuration.

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
Map explicit and implicit claims to: KS, IND, INT, EA, MA, KA, FS, PCS,
FUT (future secrecy), DEN (deniability), ANO, REPLAY, DG (downgrade),
KCI, UKS, BIND, FR (freshness).

### 2.3 Threat model
List in-scope adversaries: passive, Dolev-Yao, malicious peer/server/client,
compromised PKI, cross-protocol, future/quantum/HNDL, global passive. Mark
out-of-scope items. Flag claims that are impossible under the chosen model.

### 2.4 Handshake analysis
For every message check:
- Freshness of nonces/ephemerals.
- Identity authenticated to the peer's transcript.
- Nothing committed before it is authenticated.
- Transcript covers all negotiation params (version, cipher, group, extensions).
- Key confirmation present (Finished/MAC over transcript).
- Per-direction keys, not shared bidirectionally.
- KEM: ML-KEM (FIPS 203) uses implicit rejection; ensure failure is not externally signaled. Explicit rejection only for classic KEMs with FO transform.
- Negotiated params are authenticated.
- Both parties contribute entropy.
- EC point validation: all DHEC and ECDSA points verified on-curve before use.
  Protect against CVE-2020-0601, CVE-2024-8344, small-order subgroup attacks.

### 2.5 State machine
List states, triggers, guards, side effects. Look for stuck states,
missing error transitions, resumption confusion, rollback, stale-message replay.

### 2.6 Invariants
Verify each row explicitly:
- Fresh ephemeral per session.
- Ephemeral mixed into session key.
- Long-term keys never directly encrypt or MAC session data.
- Nonces unique within a key lifetime.
- KDF has domain separation and transcript context.
- Per-direction keys.
- Identities and negotiation params bound to session key.
- KEM failures indistinguishable from random; ML-KEM uses implicit rejection (no ⊥ signal).
- Replay/downgrade of Finished detectable.
- Resumption and 0-RTT isolated.
- Key confirmation present.
- All EC points verified on-curve; small-order and identity points rejected.

### 2.7 Naming / binding
Trace every identity/name to the key that authenticates it. Flag:
- channel-bound but not identity-bound keys,
- identity-bound to unauthenticated keys (KCI),
- channel ID reuse (UKS),
- group ID not bound to membership.

### 2.8 Primitive selection
Flag disallowed: MD5, SHA-1, DES/3DES, RC4, RSA-PKCS#1 v1.5 sigs, RSA < 2048,
DH/ECDH < 224, non-standard curves.

Acceptable: AES-GCM/CCM, ChaCha20-Poly1305, SHA-2/3, BLAKE2/3, HMAC, HKDF,
X25519/Ed25519, P-256/P-384, ECDSA-P256 with RFC 6979, RSA-PSS/OAEP,
ML-KEM/ML-DSA (hybrid; formerly CRYSTALS-Kyber/CRYSTALS-Dilithium).

Flag for special review: GOST R 34.10/34.11, SM2/SM3/SM4 (Russia/China
regional algos); confirm domain parameters, KDF binding, and no cross-protocol
reuse. Also check: version-negotiation path, mandatory algorithms, fallback
prohibition for deprecated algorithms.

**Chinese national crypto (GM/T series) — extra scrutiny:**
- SM2: ECDSA-analog with different curve equation (y² = x³ + ax + b over
  F_p); verify: point-on-curve validation, cofactor clearing, nonce requirements.
  Signature scheme is NOT compatible with ECDSA — cross-protocol key reuse is
  NOT safe. SM2 signatures must include a Z_A or user ID binding (GM/T 0009).
  Historical: no known forgeries against SM2 as used in TLS, but verify the
  KDF (SM3-based) is used, not a custom hash.
- SM3: Merkle–Damgård hash over 256-bit state; no known collision attacks
  published but younger than SHA-2. Use only where spec mandates (e.g.,
  GM/T 0024-2014 SSL). Do NOT substitute SHA-256 in non-SM contexts.
- SM4: 128-bit block cipher in CTR/OFB/CBC modes; equivalent security to
  AES-128 but no interop. Check: IV/nonce uniqueness per mode (same as C1/C6).
  AVOID mixed-mode compositions (e.g., SM4-CBC + HMAC-SM3 vs AES-GCM).
- SM9: Identity-based encryption; review master key escrowing, key isolation
  requirements, and whether the IBE scheme is IND-CCA2 under the BDH assumption.
- Cross-standard confusion: SM2 keys are not X.509 SPKI; SM9 keys use a
  different OID scheme. Verify the protocol wire format does not confuse
  SM2/SP 800-56A parameter sets with X9.62/X9.63 EC groups.

### 2.9 Proof strategy
Record: proof model (game-based / UC / symbolic), assumptions, coverage
(full or fragment), whether strong claims lack proof.

### 2.10 Attack-pattern checker
Cross-reference the design against the catalog in §3. For each Yes, write a
finding with severity, location, attacker scenario, affected goals, real
references, fix suggestion. Do not invent CVEs.

**Severity rubric.**

| Severity | Definition |
|----------|------------|
| Critical | Trivial break of EA/KA/KS/IND/FS by DY adversary |
| High | Break under realistic adversary (MITM, malicious peer) |
| Medium | Weakened property, downgrade window, missing proof |
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
- A7 — Cross-protocol key reuse.
- A8 — Trust-on-first-use without downgrade protection.
- A9 — Long-term key used directly as session key.

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
- K1 — KDF without domain separation.
- K2 — KDF without transcript context.
- K3 — Same input bytes used for multiple sub-keys.
- K4 — HKDF salt/context reused across sessions or protocols.
- K5 — Password stretched with only a hash (no PBKDF2/Argon2).
- K6 — Bidirectional keys derived without per-direction labels.
- K7 — Master secret used directly as application key.
- K8 — Cross-version KDF reuse.
- K9 — DRBG output reused with same personalization.
- K10 — Non-contributory key agreement: one party forces the shared secret.
- K11 — Missing key confirmation.
- K12 — SM3-based KDF used without GM/T-mandated counter mode; KDF
    instantiated as hash(master || label || counter) without HMAC structure.
- K13 — GM/T-specified MAC (e.g., SM4-CBC-MAC) used without domain
    separation between MAC and encryption keys.

### Confidentiality / encryption
- C1 — Nonce reuse under the same key (AEAD).
- C2 — CBC without MAC or MAC-then-encrypt without authenticated tag.
- C3 — CBC + Encrypt-then-MAC misimplemented.
- C4 — ECB for structured/variable data.
- C5 — CTR with reused counter.
- C6 — Stream cipher with reused nonce.
- C7 — KEM decapsulation failure distinguishable (ML-KEM uses implicit rejection — ensure no timing/error leak; explicit-rejection KEMs must return ⊥ in constant time).
- C8 — Compressed-then-encrypted.
- C9 — Length leakage via padding.
- C10 — Same key used for both directions.
- C11 — Nonce not guaranteed unique but non-misuse-resistant AEAD used.
- C12 — Online decryption / partitioning oracle.
- C13 — SM4 modes (CTR/OFB/CBC) reuse IV; SM4-GCM/GMAC-style composition
  not verified against national spec (GM/T 0024-2014).
- C14 — AEAD lacks key commitment: same ciphertext decryptable under
  multiple keys in multi-recipient settings.

### Forward / future / post-compromise
- F1 — No ephemeral contribution to session key.
- F2 — Static DH claimed to provide FS (rotation does not create FS).
- F3 — No ratchet / no fresh DH per message.
- F4 — Symmetric-only ratchet.
- F5 — Long-term key directly encrypts session traffic.
- F6 — No PQ / no hybrid for long-term confidentiality.
- F7 — HSM-stored key with no forward-mitigation plan.
- F8 — Resumption reuses old keys without fresh contribution.
- F9 — No recovery from long-term key compromise.

### Point validation / EC
- PV1 — EC point not verified on-curve → scalar multiplication leaks bits (CVE-2020-0601 for EdDSA, CVE-2024-8344).
- PV2 — Small-order or identity point accepted in DH → total break.
- PV3 — Compressed point decoded without y-coordinate check → invalid-point oracle.
- PV4 — Cofactor not checked in ECDH → small-subgroup / torsion-point attack.
- PV5 — ECDSA point not verified before signature verification → signature forgery.

### Signatures
- S1 — RSA-PKCS#1 v1.5 signature forgeries (Bleichenbacher 2006).
- S2 — ECDSA with biased or non-deterministic nonces.
- S3 — Ed25519 without domain separator (Ed25519ctx).
- S4 — No hash-of-message before signature.
- S5 — Signature excludes part of the transcript.
- S6 — No domain separation between signature purposes.
- S7 — Rogue key / key substitution attack.
- S8 — SM2 signature used outside its mandated GM/T profile; Z_A/user-ID
  binding missing or ignored (GM/T 0009 §5.1).
- S9 — SM2 key format confused with X9.62/X9.63 EC key; parameter-set
    mismatch enables cross-protocol attack.
- S10 — ML-DSA signature context string (`ctx`) omitted or reused across
  protocol operations (FIPS 204).

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
- PQ1 — Hybrid combiner using XOR instead of dual PRF.
- PQ2 — KEM public key not authenticated.
- PQ3 — Classic and PQ shares not independently contributed.
- PQ4 — PQ ciphertext not bound to transcript.
- PQ5 — Implicit-rejection bypass.

### Group / multi-party
- GP1 — Sender key not bound to group membership.
- GP2 — Membership change does not update group key.
- GP3 — Members disagree on group epoch / partition.
- GP4 — Removed member retains decryption ability.
- GP5 — Group creator controls all keys (no contributory).

### Metadata / traffic analysis
- M1 — Unencrypted metadata leaks identity/membership/presence.
- M2 — Message size/timing leaks content.
- M3 — No padding or traffic-shaping strategy.
- M4 — Alerts not encrypted; distinguish close_notify from bad_record_mac.

### Modern frameworks (Noise / HPKE)
- MF1 — Noise pattern chosen does not match required authentication or
  forward-secrecy level (e.g., `Noise_N` with unrotated server static key).
- MF2 — HPKE `Auth`/`AuthPSK` mode used but `enc` not authenticated under
  sender identity; exporter secret reused without distinct `exporter_context`.

### PAKE
- P1 — Password verifier equivalent to password.
- P2 — Offline dictionary attack on transcripts.
- P3 — No rate limiting / client puzzle.

### Revocation / recovery
- REV1 — No key revocation mechanism.
- REV2 — Compromised device cannot be excluded.
- REV3 — No recovery from long-term key compromise.

### Composition
- CP1 — Same key material used in multiple protocol contexts.
- CP2 — Nested sessions without domain separation.
- CP3 — Two protocols sharing a PKI interact dangerously.
- CP4 — SM2/ECIES keys used with X9.62 parameter sets or vice versa
  (curve confusion; cf. CVE-2020-0601 class).
- CP5 — SM9 IBE master key escrowed but not isolated; key-encapsulation
  delegation without revocation check.
- CP6 — Transcript hash vulnerable to collision or prefix injection;
  encoding ambiguity enables equivalent-transcript attacks.

### Encoding / wire format
- E1 — Ambiguous length fields or duplicate fields parsed inconsistently
  across implementations, enabling transcript manipulation.

### Deniability
- DEN1 — Non-repudiable signatures break deniability.
- DEN2 — Online vs offline deniability mismatch.

### Design smells
- I1 — Length-extension on SHA-2 (use HMAC or SHA-3).
- I2 — Asymmetric encrypt-and-sign without careful binding.
- I3 — Custom padding.
- I4 — Password used as direct key.
- I5 — No protocol versioning at all.
- I6 — Session bound to network location (IP/VPN) — breaks on mobility.
- I7 — Resumption ticket age not bound to session; no abbreviated vs 0-RTT distinction.

---

## 4. Output Format — `findings.md`

```markdown
# Protocol Review: <name> v<version>

**Scope:** protocol logic only
**Source:** <link/path>

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
- **Affected goals:** G3 (FS), G1 (KS)
- **References:** CVE-XXXX-XXXX / paper
- **Fix:** ...

## Coverage Matrix
| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
```

---

## 5. Validation Example — FooChat 1.0 (Custom, with PLANTED flaws)

**Spec.**
```
C → S: { v:"1.0", c_rand, ciphers:[AES256GCM,AES128GCM,ChaCha20], groups:[X25519] }
S → C: { v:"1.0", s_rand, cipher, s_eph }
C → S: { c_eph, user:"alice@example.com" }
S → C: { sig = Ed25519(sk_s, SHA256(c_rand||s_rand||cipher||s_eph||c_eph||user)) }

MS = SHA256(c_rand || s_rand || ECDH(sk_s,pk_c) || ECDH(sk_eph,pk_c) || user)
k_c2s = HKDF(MS, "c2s", 16)   k_s2c = HKDF(MS, "s2c", 16)
nonce_c = 0, nonce_s = 0, incremented per message

App data: AES-128-GCM with k_c2s/nonce_c for C→S, k_s2c/nonce_s for S→C.
No client authentication.
```

**Expected findings.**

| # | Sev | Pattern | Finding |
|---|-----|---------|---------|
| F-001 | Critical | A1 | No client auth — anyone can claim any user. |
| F-002 | Critical | K2 | `MS` lacks transcript binding — cipher/version can be downgraded undetectably. |
| F-003 | High | A2/K11 | No client Finished/key confirmation — UKS possible. |
| F-004 | High | F1/F2 | Static-static ECDH in `MS` gives no forward secrecy. |
| F-005 | High | F6 | No PQ contribution — HNDL vulnerability. |
| F-006 | Medium | K1 | Minimal HKDF context — cross-context key reuse hazard. |
| F-007 | Medium | RD6 | No rekey boundary; counter starts at 0 each session. |
| F-008 | Medium | K10 | Server freely chooses `s_eph`; combined with missing key confirmation, key-control risk. |
| F-009 | Medium | N1 | No Finished binds `cipher`; downgrade undetectable. |
| F-010 | Medium | S3/S6 | Ed25519 without context/domain separation — cross-protocol forgery. |
| F-011 | Medium | I1 | Raw SHA-256 used as KDF; extraction step missing. |
| F-012 | Low | F9 | No compromise recovery. |
| F-013 | Info | FUT | Recommend hybrid ML-KEM+X25519. |

**Verdict: FAIL.**

---

## 6. Brief Notes on Well-Known Protocols

- **TLS 1.3** — PASS-WITH-FIXES: downgrade protected by `supported_versions`
  + transcript + downgrade random; 0-RTT replayable by design; no PQ/HNDL.
- **X3DH → PQXDH** — PASS-WITH-FIXES: hybrid X25519+ML-KEM via HKDF-Extract;
  watch downgrade window and authenticate PQ public key under identity key.

---

## 7. References

- RFC 8446 (TLS 1.3), RFC 9180 (HPKE), RFC 9420 (MLS), RFC 8032 (Ed25519).
- Signal: X3DH, PQXDH.
- NIST FIPS 203/204/205 (PQC), SP 800-131A Rev.2.
- Tools: ProVerif, Tamarin, Verifpal.
- Attacks: Bleichenbacher, ROBOT, FREAK/Logjam, KRACK, Triple Handshake.