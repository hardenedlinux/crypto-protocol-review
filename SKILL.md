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

Escalate implementation findings (timing leaks on key confirmation,
non-constant-time comparison, RNG state) to a code-audit skill.

A review is complete when every claim is mapped or marked unmet, every
message is traced, every catalog pattern is answered Yes/No/N/A, every
severity has a concrete attacker scenario, and `findings.md` includes the
full §4 `## ⚠️ Important Limitations` block verbatim (see §4).

---

## 2. What to Check at Each Stage

### 2.1 Spec extraction
Extract into `protocol-model.json`:
- Roles, messages (direction + fields), primitives, keys, protocol state,
  out-of-band channels, negotiated parameters, session modes (full /
  resumption / external-PSK / 0-RTT / post-handshake auth / mid-session rekey /
  mid-session re-handshake), identity/credential types, transport (stream vs
  datagram).

### 2.2 Security goals
Map explicit and implicit claims to: KS (Key Secrecy), IND (Indistinguishability), INT (Integrity),
EA (Encryption Authenticity), MA (Message Authenticity), KA (Key Authenticity),
FS (Forward Secrecy), PCS (Post-Compromise Security / self-healing), FUT (Future Secrecy / recovery),
HNDL (Harvest-Now/Decrypt-Later / long-term PQ confidentiality — record generic vs explicit NIST category / AES-equivalent if stated),
DEN (Deniability), ANO (Anonymity — no dedicated §3 pattern; flag as Info gap if claimed; see M1–M3 for metadata/timing leakage),
REPLAY, DG (Downgrade), KCI (Key Compromise Impersonation), UKS (Unknown Key-Share), BIND (channel/identity binding), FR (Freshness).

### 2.3 Threat model
List in-scope adversaries: passive, Dolev-Yao, malicious peer/server/client,
malicious group member (if multi-party), long-term key compromise (drives FS),
session-key/ephemeral-key or full state compromise (drives PCS), resumption
ticket/PSK sealing-key compromise (drives R8/F8), compromised PKI,
cross-protocol, future/quantum/HNDL (score F6 against the stated HNDL
level: generic/silent vs explicit NIST category-1 / AES-128-equivalent),
global passive. Multi-recipient / group / fan-out encryption (same
ciphertext under multiple recipient keys, or sender-keys fan-out):
multi-key confusion (C14) is in scope by default. Mark out-of-scope
items. Flag claims that are impossible under the chosen model. When
the spec is silent: assume a Dolev-Yao network adversary; treat mutual
auth, FS, PCS, HNDL, DEN, and ANO as required only if claimed or
clearly implied by the protocol class (e.g. messaging ratchet → FS/PCS;
TLS-like server-auth channel → server auth + handshake-ephemeral FS —
not client auth or HNDL).

### 2.4 Handshake analysis
Map each message to the catalog entries it must satisfy.
- Freshness & lifetime: fresh nonces/ephemerals per handshake, rekey within the nonce collision limit (RD6, RD7).
- Authentication before key use: peer identity and all negotiated params (version, cipher, group, extensions) are authenticated and included in a collision-resistant transcript (S5, N1–N4, CP5, K11). Do not accept application data under traffic keys, or expose exporters/channel-binding tokens, until the required peer authentication and key confirmation complete (unilateral auth suffices when only one side is authenticated; offline/async AKE may defer mutual confirmation to the peer's first reply — do not claim mutual auth before that; intentional 0-RTT per R7/R7b). Do not send reusable credentials (bearer tokens, API keys, password forms) to a peer before that peer is authenticated when the threat model requires peer auth — includes credentials under keys that do not yet authenticate the recipient (MITM harvest); N/A for PAKE password contributions used as protocol inputs (P1–P3).
- Key derivation: domain-separated labels, transcript context (including exporters/channel-binding tokens), HKDF-Extract (or equivalent) on non-uniform IKM (always for DH shared secrets and for hybrid shares; Expand-only only if IKM is already a single high-entropy PR key of length ≥ HashLen, e.g. sole ML-KEM ss with SHA-256 or SHA-512/256 — not raw `ss_classic||ss_pq`, not Expand-only into SHA-384/512 on a 32-byte ss), per-direction keys, no cross-version reuse (K1, K2, K3, K4, K6, K8).
- 0-RTT: R7, R7b, F8 — replayable by design; early-data keys PSK/ticket-bound (no FS vs ticket compromise; TLS 1.3 `psk_dhe_ke` DHE does not protect early data); reject on param divergence; anti-replay durable across restart and across multi-endpoint acceptors sharing the ticket/PSK, or reject 0-RTT / single-use tickets.
- Resumption: R8, I7, A3, A5, K2 — tickets unforgeable with lifetime/rotation; bind all identities and client-auth status authenticated on the session **at ticket issue** (incl. post-handshake auth completed before issue — not only the full-handshake subset; pre-auth tickets need not be invalidated after later post-handshake auth — issue-time status is authoritative on resume), server name, version/cipher/group, KE mode (PSK-only vs PSK+DHE), hybrid/PQ suite identity when multiple suites or acceptor policies can diverge (R8 N/A limb if single fixed suite for sealing-key lifetime + uniform acceptor policy), ALPN; multi-endpoint acceptors sharing a sealing key must enforce **all** bound context (version/cipher/group/KE mode/hybrid suite/ALPN/identities incl. server name) against local policy — not only hybrid suite/KE mode; Triple Handshake-class if binders omit full auth context.
- Negotiation: N1–N7, A8, R3–R5 — offer lists **and** selections for version/cipher/group/extensions in the authenticated transcript (not merely present in a cleartext hello); hello-retry cookie bound to ClientHello; optional plaintext→secure upgrade must not be strippable to plaintext without detection (STARTTLS-class); deprecated algorithms not offerable when a secure alternative exists (N7). Datagram: address-validation before large responses (N6 — cookies/retry tokens; not P3b client puzzles).
- Key agreement: DH contributory (K10 = small-order/identity only); static-static → F1/F2/A4 not K10; standalone IND-CCA2 KEM OK; authenticate KEM PK (PQ2).
- PQ hybrid: PQ1–PQ4 — non-strippable classic+PQ shares; concat-then-Extract / SP 800-56C or dual-PRF Extract(salt, IKM) (not Expand-only on raw concat, not one share omitted, not raw XOR/concat as traffic key; Expand(PRK=ss1, info=ss2) is not dual-PRF — needs its own proof; prefer both shares in Extract); bind PQ PK auth + ciphertext to transcript; dual/composite sigs non-strippable when post-CRQC auth claimed (PQ3).
- FS/PCS vs rekey: handshake ephemerals give per-session FS (F1/F8); continuous messaging needs a ratchet for long-lived FS/PCS (F3/F4/F9). Mid-session KeyUpdate-class rekey under current traffic keys is RD6/RD7 — not a DH ratchet and not F3/F4; it is not PCS recovery (F9).
- Validation: EC point validation (PV1–PV5, with X25519/X448 all-zero check); KEM decapsulation failures indistinguishable, prefer implicit rejection (C7); finite-field DH validates (p, q, g) and that 1 < Y < p-1 and Y^q ≡ 1 mod p.
- Frameworks: Noise pattern matches required auth/FS level (MF1); HPKE Auth/AuthPSK binds static key to identity and adds explicit key-confirmation MAC when required (MF2).
- PAKE: verifier not password-equivalent, transcripts resist offline attack, rate-limiting, optional client puzzle (P1–P3, P3b).

### 2.5 State machine
List states, triggers, guards, side effects; keep full handshake, resumption,
external-PSK, 0-RTT, post-handshake auth, and rekey as distinct modes (I7).
Verify transitions cover error, rekey (auth under current traffic keys — RD6),
post-handshake auth (bind to current session transcript — A2/A5/K11; tickets
  issued afterward must include the new identities — R8/A5), mid-session
  re-handshake if any (I7: new handshake transcript must include a prior-session
  binder — Finished, session-hash, or post-auth exporter — covering prior
  authenticated identities/client-auth; not early-secret/0-RTT exporters; not a
  silent unbound full handshake), recovery (if PCS claimed — F9), and
  shutdown/alert paths (M4 — including authenticated end-of-stream so truncation
  is detectable); do not enter application-data state or expose exporters/channel
  binders before required peer auth/key confirmation (K11; intentional 0-RTT per
  R7/R7b); reject unexpected handshake message types, wrong-epoch messages, and
  silent state skips (I7 — datagram reordering of concurrent expected-flight
  messages is OK); reject re-acceptance of Finished/key-install that reinstalls
  the same traffic keys or resets nonces/replay counters once keys are live (R1 —
  KRACK-class, not I7 mode confusion); reject 0-RTT after hello-retry, param
  divergence, or lost/unshared anti-replay state (R7b); guard stuck/half-open
  sessions; anti-replay overflow (R9). Datagram: no large response before
  address validation (N6). Check I7, A5, N1–N7, R1, R3–R9, RD6, RD7, M4, F9, I6, K11.

### 2.6 Invariants
Session-lifetime checks beyond the handshake (catalog cross-refs only):
- 0-RTT: R7, R7b, F8
- Resumption: R8, I7
- Rekey / nonce lifetime: RD6, RD7
- PCS/FUT if claimed: F9 (KeyUpdate alone ≠ PCS — F4)
- HNDL if claimed: F6 (path presence/strip + AEAD/KEM sizing), PQ1
  (combiner — separate ownership), PQ2–PQ4 (PK auth, strip, CT bind)
- Continuous: PV1–PV5, C7, R9, I6, M4 (negotiation R3–R5 / N1–N4 and
  transcript auth K11/S5/CP5 are handshake or re-handshake — §2.4 / I7)

### 2.7 Naming / binding
Trace every identity/name to the key that authenticates it. Application-intended
peer names (hostname/SNI, user ID, service identity) must be verified against
the authenticated credential — not merely that some valid key completed the
handshake (A5, S7). Resumption tickets/PSKs and channel-binding/exporter tokens
must carry the authenticated application names and client-auth status as of
ticket issue / exporter export (incl. post-handshake auth; A3, A5, R8).
External/provisioned PSKs must bind the intended peer name at provisioning
(app-layer association OK) or in the handshake transcript under key
confirmation (A5); pure-PSK without independent peer auth needs at least one.
When no application name exists (raw-pubkey TOFU, anonymous Noise),
name-binding is N/A; still check A2/S7 if an identity is claimed. Flag catalog
entries A2–A9, CP2, GP1, GP3, K11, S5, S7.

### 2.8 Primitive selection
Disallowed:
- Hashes/MACs: MD5 (incl. HMAC-MD5); SHA-1 for collision-resistant uses (certs, signatures, transcripts) and for new KDF/HKDF/PRF hash — disallowed. HMAC-SHA-1 only as a MAC in legacy interop (not as hash/KDF): if a profile still mandates it for new sessions, score Low (interop smell), not Critical; elevate if used collision-sensitively or as HKDF/PRF hash. SHA-224 / SHA-512/224 only for ≤112-bit targets (same floor as P-224).
- Symmetric: DES/3DES, RC4, other 64-bit block ciphers (Blowfish, IDEA, CAST5 — Sweet32).
- Signatures: DSA (removed in FIPS 186-5 — no new signatures; legacy verification only if interop requires); RSA-PKCS#1 v1.5 for newly generated protocol signatures (S1) — use RSA-PSS; verifying existing PKI/certs that already use PKCS#1 v1.5 is OK when full padding is validated.
- Key transport: RSA-PKCS#1 v1.5 encryption (C15). RSA-OAEP (RFC 8017) and RSA-KEM (ISO/IEC 18033-2) are acceptable IND-CCA2 transport but give no FS under LT private-key compromise (F1) unless combined with ephemeral agreement the LT key cannot recompute.
- Parameters: RSA <2048, finite-field DH <2048, ECC prime-field curves (ECDH/ECDSA) <224-bit, all binary/char-2 curves (sect*), Dual_EC_DRBG, ANSI X9.31 PRNG, custom/unnamed curves without published security analysis, known-broken curves (anomalous, supersingular over small fields, etc.). Named non-NIST curves (e.g. secp256k1, Brainpool) are not auto-disallowed — special-review domain parameters and cross-protocol key reuse.
  Absolute floors ≈112-bit (SP 800-57). Default classical target is 128-bit when the spec is silent. For 128-bit require RSA ≥3072, FF-DH ≥3072 (named groups, e.g. RFC 7919), ECC ≥256-bit prime field or X25519/X448. Sub-threshold params (P-224 / FF-DH-2048 / RSA-2048): Info/Low when the spec is silent (skill default only); Medium when the protocol explicitly claims ≥128-bit classical security; N/A or OK if a ≤112-bit claim is explicit. Do not mark Critical for parameter-size gaps alone unless sizes are practically breakable today.

Acceptable:
- AEAD: AES-GCM, AES-GCM-SIV, AES-SIV (RFC 5297), AES-CCM, ChaCha20-Poly1305, XChaCha20-Poly1305, Ascon-AEAD128 (NIST SP 800-232; lightweight; not nonce-MR — C1). Classical 128-bit target: AES-128 or AES-256 (or ChaCha20) is fine; HNDL AEAD sizing per F6. RFC 5297 AES-SIV-N: N is total SIV key bits (two AES keys) — AES-SIV-256 = AES-128 strength; AES-SIV-512 = AES-256 strength — do not treat “256-bit SIV key” as a 256-bit security target.
- Hash/MAC/KDF/XOF: SHA-2/3 (SHA-256+ for 128-bit targets; see SHA-224 floor above; transcript collision strength per CP5 — not the same as KDF PRF/HashLen), SHAKE128/256 (FIPS 202 XOF; SHAKE128 only for ≤128-bit targets; for collision-resistant uses outlen ≥ 2× claim within capacity: SHAKE128 outlen≥256 → ≤128-bit; SHAKE256 outlen≥256 → ≤128-bit, outlen≥384 → ≤192-bit, outlen≥512 → ≤256-bit — not the XOF name alone), BLAKE2 (hash/KDF/MAC), BLAKE3 (hash/KDF/XOF; compliance permitting), HMAC-SHA-256/384/512 (incl. SHA-512/256 where HashLen=32), AES-CMAC (SP 800-38B), HKDF-HMAC-SHA-256+ (RFC 5869; not SHA-1; Expand-only HashLen per K3), SP 800-108 KDF (counter/feedback/double-pipeline), KMAC128/256 as MAC or KDF per SP 800-185 / SP 800-56C (KMAC128 only for ≤128-bit targets; not “HKDF with KMAC”).
- DH: X25519/X448, P-256/P-384/P-521, FF-DH with named groups at the size floor (e.g. RFC 7919 ffdhe≥3072 for 128-bit).
- Signatures: Ed25519 (use Ed25519ctx with protocol context when cross-protocol domain separation is needed; plain Ed25519 is fine for single-protocol use), Ed448 (native context per RFC 8032; non-empty when cross-protocol/purpose separation is needed, empty OK for single-protocol use; Ed25519ph/Ed448ph when prehash is required), ECDSA (RFC 6979 or FIPS 186-5 deterministic nonces preferred — S2; match hash to curve strength per SP 800-57/FIPS 186-5: P-256↔SHA-256, P-384↔SHA-384, P-521↔SHA-512 — weaker hash caps EUF at hash collision strength), RSA-PSS.
- KEM / key transport: IND-CCA2 only — RSA-OAEP (RFC 8017); RSA-KEM (ISO/IEC 18033-2); ML-KEM (FIPS 203; 512/768/1024 ≈ NIST categories 1/3/5 — match claim; for generic HNDL prefer 768+; ML-KEM-512 OK only under an explicit category-1 claim); other standardized IND-CCA2 KEMs OK at matching strength. CPA-only KEMs are disallowed for session key exchange. ML-KEM has no application `ctx` — domain-separate via outer KDF info/label (never raw ss as traffic key; Expand-only only when len(ss) ≥ HashLen — K3). Encaps to a long-term KEM PK alone is not FS (F1).
- PQ signatures: ML-DSA (typical for handshake size; 44/65/87 ≈ NIST cat 2/3/5); SLH-DSA (stateless hash-based; prefer over XMSS/LMS); match parameter sets to the security target; distinct `ctx` per protocol/purpose (FIPS 204/205). Dual/hybrid/composite signatures: verify all components when post-CRQC auth is claimed (non-strippable — PQ3).

Special review: regional algorithms (GOST R 34.10/34.11, SM2/SM3/SM4/SM9) — confirm domain parameters, KDF binding, and no cross-protocol reuse. Stateful hash-based signatures (XMSS/LMS, SP 800-208) — NIST-approved but state reuse is catastrophic; prefer SLH-DSA unless single-use state is enforced by design (e.g. HSM). Also check version-negotiation path, mandatory algorithms, and prohibition of fallback to deprecated algorithms.

**Chinese national crypto (GM/T series) — extra scrutiny:**
- SM2: ECDSA-analog with different curve/signature (not ECDSA-compatible —
  no cross-protocol key reuse). Verify on-curve/cofactor, nonces, Z_A user-ID
  binding (GM/T 0009 §5.1). Key-exchange KDF is SM3 counter-mode (K12), not
  HMAC; reject ad-hoc replacements (GM/T 0024-2014 TLS profile).
- SM3: MD hash, 256-bit state; use only where the profile mandates. No known
  collisions published; younger than SHA-2. Do not substitute SHA-256 in
  non-SM contexts (or SM3 in non-SM profiles).
- SM4: 128-bit block cipher and 128-bit keys only (~AES-128). IV/nonce
  uniqueness per mode (C1/C6). Prefer SM4-GCM per GM/T 0069-2018 over
  ad-hoc SM4-CBC+HMAC-SM3 when the profile allows. Under generic/silent
  HNDL (F6) treat as AES-128 traffic keys (Medium partial) — cannot meet
  the ≥256-bit AEAD-key default; OK only if the claim is explicit cat-1 /
  AES-128-equivalent.
- SM9: IBE — master-key escrow/isolation, revocation, IND-CCA2 under the
  profile's q-type bilinear assumptions (not plain BDH).

### 2.9 Proof strategy
If a formal proof or reduction is claimed, verify the reduction target
(IND-CCA2 for KEMs/public-key encryption, EUF-CMA for signatures,
INT-CTXT / AEAD, PRF/RO for KDFs, etc.) matches the goal and threat
model, the assumptions are listed explicitly, and any ideal-model
assumptions (ROM, ICM) are consistent with the chosen primitives. For
downgrade-resistance claims, verify the reduction treats version/cipher/
group/extensions as part of the authenticated transcript (N1–N5, CP5).
Flag missing multi-instance / multi-key lemmas where multi-recipient
settings are claimed; hybrid KEM/KE without a combiner security argument
when hybrid or HNDL is claimed (either-share KS: PQ1 / SP 800-56C
concat-then-Extract or dual-PRF Extract(salt, IKM); Expand(PRK=ss1,
info=ss2) is not dual-PRF — needs its own proof; raw-concat as traffic key
without Extract/KDF is not an argument); honest-vs-malicious recipient
mismatches in CPA→CCA upgrades; and inconsistent modeling of KEM
decapsulation failures (implicit vs explicit rejection, C7) relative to
the adversary's oracle access. Most protocol specs only have informal
arguments — that is not a FAIL: record "informal only" in
`proof-sketch.md` (Info). Raise a finding when (a) a formal proof is
claimed but missing, broken, or mismatched to the goals/threat model
(Medium–High), or (b) a goal is claimed with no argument at all under
the stated adversary (Medium).

### 2.10 Attack-pattern checker
Cross-reference the design against the catalog in §3. For each Yes, write a
finding with severity, location, attacker scenario, affected goals, real
references, fix suggestion. Do not invent CVEs. One finding per root cause:
when several patterns match the same defect (e.g. PQ1+(F6 affected goal),
R8+A5 ticket identity), list all Pattern IDs on a single finding — do not
stack severities or emit duplicate Critical/High rows.

**Severity rubric.**

| Severity | Definition |
|----------|------------|
| Critical | Full break of any claimed goal from §2.2 under the threat model in which it is claimed (e.g. HNDL claimed but no non-strippable PQ/hybrid path). Missing FS/PCS/HNDL/DEN/mutual-auth is Critical only when explicitly claimed. |
| High | Break under MITM/malicious peer of a property the silent/default model in §2.3 requires or that the protocol class clearly implies (e.g. negotiation binding, key confirmation, TLS-class handshake-ephemeral FS) or that the written model understates; or material weakening of a claimed FS/PCS/downgrade property. |
| Medium | Partial/weakened claimed goal (e.g. generic HNDL with hybrid KEM but 128-bit AEAD keys — AES-128-*/AES-SIV-256/Ascon-AEAD128/SM4 — or cat-1-only KEM; not when the claim is explicitly NIST category 1), bounded downgrade window, or reasoning gap that could affect a goal. |
| Low | Footgun / design smell / future-proofing (unclaimed and not §2.3-implied FS/PCS/HNDL/DEN/ANO). |
| Info | Observation / clarification. |

`Enforced=Partial` is coverage-matrix only — never a finding **Severity** value (see F1).

---

## 3. Attack Pattern Catalog

Check every pattern below. Mark Yes/No/N/A with one-line reasoning.

### Authentication / identity
- A1 — Missing mutual authentication when claimed or required by the threat
  model → MITM (N/A if intentionally unilateral and the model matches). Also
  flag reusable credentials (bearer tokens, API keys, password forms) sent
  before the receiving peer is authenticated when peer auth is required —
  including under keys that do not yet authenticate that peer (MITM harvest);
  N/A for PAKE inputs (P1–P3); and optional peer-auth messages (e.g.
  CertificateRequest / client Certificate) that can be stripped because they
  are not transcript-bound.
- A2 — Unknown key-share (UKS): handshake authenticated but key shared with
  wrong peer.
- A3 — Channel-binding token / exporter reused across users or sessions, or
  derived without binding peer identity **and** the full handshake transcript
  through key confirmation (pre-Finished / incomplete auth → Triple
  Handshake-class splicing; or post-handshake auth completed before export
  but omitted from the bound transcript): same binder presented on different
  sessions or by different peers (cf. K2, K11, R8). Connection IDs that are
  only public demux handles are N/A here (see RD1); flag only when a CID is
  used as a binder or authorization token.
- A4 — Key compromise impersonation (KCI): compromise of A's long-term key
  lets the attacker impersonate other parties *to* A (static-static DH and
  some AKEs without ephemeral contribution on the peer side).
- A5 — Identity misbinding: parties disagree on who shares the key, or the
  authenticated credential is not bound to the application-intended peer name
  (hostname/SNI, user ID, service identity): PSK/ticket not bound to **all**
  identities and client-auth status authenticated on the session at ticket
  issue (incl. post-handshake auth completed before issue; tickets issued
  earlier must not gain later identities — issue-time status is authoritative
  on resume; invalidating pre-auth tickets after later post-handshake auth is
  optional hardening, not required); external/provisioned PSK not bound to
  the intended peer name at provisioning (app-layer association OK) **or** in
  the handshake transcript under key confirmation — pure-PSK without
  independent peer auth needs at least one; post-handshake credential not
  bound to the current session transcript → splicing or UKS-class confusion;
  or any valid cert/key accepted without matching the intended name (cf. A2,
  R8, K11, S7). N/A only when no application-intended peer name exists
  (raw-pubkey TOFU, anonymous Noise); if a name exists, "some valid key"
  without name match is Yes — not N/A. Still apply A2/S7 when an identity is
  claimed.
- A6 — Reflection / selfie: party accepts its own ephemeral, key share, or
  handshake message as the peer's contribution (missing role separation or
  self-message rejection).
- A7 — Cross-protocol or cross-purpose key reuse: same key material in multiple protocol contexts or for different cryptographic purposes (e.g., signing and key agreement).
- A8 — Trust-on-first-use without key-change detection: after the first
  connection, no mechanism exists to detect or reject a MITM-forced key
  swap on subsequent connections.
- A9 — Long-term key used directly as session key.

### Composition
- CP1 — Nested sessions or protocols without domain separation.
- CP2 — Certificate/trust-anchor namespace collision: two protocols share a CA or certificate namespace without name separation, enabling cross-protocol issuance or impersonation.
- CP3 — SM2/ECIES keys used with X9.62 parameter sets or vice versa
  (curve / parameter-set confusion).
- CP4 — SM9 IBE master key escrowed but not isolated; key-encapsulation
  delegation without revocation check.
- CP5 — Transcript hash vulnerable to collision or prefix injection;
  encoding ambiguity enables equivalent-transcript attacks; or transcript
  hash collision resistance below the protocol's classical security target
  (need ~2× claim in digest/XOF outlen, within capacity: silent/≤128-bit →
  SHA-256 / SHAKE128 outlen≥256 / SHAKE256 outlen≥256; explicit ≥192-bit →
  SHA-384 / SHA-3-384 / SHAKE256 outlen≥384; explicit ≥256-bit → SHA-512 /
  SHA-3-512 / SHAKE256 outlen≥512 — do not treat SHA-384 as enough for a
  256-bit claim). KDF/HKDF hash choice is not this collision limb (PRF/
  HashLen per K3; HKDF-SHA-256 may still derive 256-bit keys).

### Replay / ordering / rollback
- R1 — Replay of Finished/key-install/session-key message across sessions,
  or re-acceptance within a session that reinstalls the same traffic keys
  and resets nonces/replay counters (KRACK-class → nonce reuse under C1).
- R2 — Replay of a peer's key-exchange contribution (ephemeral share, KEM
  ciphertext, handshake nonce) accepted as fresh for a new session without
  binding to this session's unique transcript (fresh nonces/ephemerals on
  both sides + key confirmation over that transcript). Enables
  session-confusion or same-ss reuse across sessions. N/A when every KE
  contribution is covered by K11 over a session-unique transcript; Finished
  re-accept / key-reinstall is R1, not R2.
- R3 — Downgrade via version negotiation, or optional plaintext→secure
  upgrade (STARTTLS-class) where a network adversary strips the offer of
  the secure protocol and forces plaintext because the client does not
  require security / does not authenticate the upgrade decision.
  N/A if intentionally cleartext-only (no secure-upgrade claim).
  Opportunistic upgrade with undetectable strip → Yes; severity Low/Info
  if opportunistic is an explicit non-goal, or the only claim is
  "encryption when available" / best-effort (no fail-closed KS). If the
  protocol claims sticky/remembered secure-upgrade (HSTS-class: once
  upgraded, later connections must refuse plaintext), strip scores per
  claimed KS. Else per claimed KS.
- R4 — Downgrade via cipher negotiation: undetected force to a weaker
  cipher/AEAD (offer list or selection not authenticated — N1).
- R5 — Downgrade via group negotiation: undetected force to a weaker
  group/KEM (offer list or selection not authenticated — N2).
- R6 — Rollback of ratchet step: recipient accepts an older epoch /
  chain-key / root-key update (or an unauthenticated skip) so state
  reverts or jumps to an attacker-chosen prior generation → decrypt
  under restored keys or lose FS for the rolled-back span. Require
  authenticated monotonic epoch/generation counters; reject
  non-increasing updates. N/A if no ratchet (see F3/F4).
- R7 — 0-RTT not treated as replayable by design, or sender-side controls
  absent where the protocol claims replay resistance (restrict 0-RTT to
  safe/idempotent ops; sender cannot stop network replay alone).
- R7b — 0-RTT recipient lacks anti-replay window (Bloom filter/PTS/Merkle);
  anti-replay state is not durable across restart **or** not shared across
  multi-endpoint acceptors of the same ticket/PSK (must reject 0-RTT until
  rebuilt/shared, or use single-use tickets); accepts 0-RTT for sensitive/
  non-idempotent ops; accepts early data for operations that require client
  authentication when the early-data phase is not client-authenticated; or
  accepts early data when final negotiated parameters differ from those
  assumed for early-data keys (e.g. after hello-retry or cipher/group change).
- R8 — Resumption without context binding. Resumption PSK/ticket must be
  cryptographically derived from or sealed under the prior authenticated
  session (session-hash / key-schedule inheritance) — do **not** require the
  new handshake to re-hash the old transcript (that binder is I7 mid-session
  re-handshake only). Binder/ticket must carry **all** identities and
  client-auth status authenticated on the session **at ticket issue** —
  client and server when mutual/client-auth or post-handshake auth had
  completed before issue; tickets must not over-claim identities added only
  after issue; pre-auth tickets may remain valid after later post-handshake
  auth on the parent session — resume must present the weaker issue-time
  client-auth status (apps that require client auth re-check; do not flag
  non-invalidation alone); intended server name if multi-tenant;
  version/cipher/group; key-exchange mode (PSK-only vs PSK+DHE); when
  hybrid/PQ was used, the establishing hybrid/PQ group or KEM suite — not
  only a coarse hybrid/classic flag (N/A for this suite-identity limb only
  when, for the lifetime of the ticket-sealing key, a single fixed hybrid/PQ
  suite is the sole establishment path offered/accepted by every acceptor of
  that key — identical suite policy, no weaker hybrid or classic-only
  establishment selectable; per-deployment/sealing-key constancy, not
  constant across all protocol versions forever — version is a separate R8
  limb). Still require KE mode, version/cipher/group, identities,
  ALPN/app protocol where present. When tickets may be accepted by another
  endpoint sharing the ticket-sealing key: binder must carry the full context
  above (hybrid/PQ suite identity required unless the N/A limb applies);
  each acceptor must reject tickets whose bound version/cipher/group/KE
  mode/hybrid suite/ALPN/identities (incl. server name) are outside or weaker
  than local policy — binder completeness alone is insufficient without
  acceptor checks (shared sealing key + divergent acceptor policy is a
  classic cross-node downgrade/UKS path). Also: forgeable tickets/PSKs (not
  MAC/AEAD under a server key); missing ticket expiry/lifetime; ticket
  sealing keys with no lifetime/rotation (dual-key decrypt during rotation
  keeps the retired key forgeable until dropped). Ticket age / obfuscated
  age is 0-RTT anti-replay (R7b), not an R8 identity-binding limb.
- R9 — Stale or reordered message replay: missing timestamp/nonce; or
  record/datagram layer lacks sequence numbers / anti-replay window under
  the traffic key; or anti-replay state wraps/overflows without rekey so
  old records become acceptable again.

### Key derivation
- K1 — KDF without domain separation: same HKDF PRK and info/context
  label reused across sub-keys, sessions, or protocol contexts, or same
  IKM+salt reused without distinct labels, producing identical PRKs or OKMs.
- K2 — KDF without transcript context (includes exporters/channel-binding
  tokens derived without the handshake transcript).
- K3 — Non-uniform or low-entropy IKM is used directly as a key, or
   HKDF-Extract (or equivalent extractor) is omitted when IKM is not already
   high-entropy pseudorandom key material (password, user-chosen PSK,
   low-entropy secret; DH shared secret — high-entropy but non-uniform, always
   Extract; hybrid shares `ss_classic||ss_pq` are not a PRK — Extract /
   SP 800-56C with both shares as IKM and/or salt, not Expand-only). A single
   IND-CCA2 KEM ss or a uniform random key may use HKDF-Expand-only (ss as PRK)
   only if len(ss) ≥ HashLen of the HKDF hash (RFC 5869; ML-KEM ss is 32 bytes
   → SHA-256 or SHA-512/256 OK; SHA-384/512 require Extract first or a longer
   PRK); still domain-separate via info/label — not raw ss as traffic key; see
   K1, K7. Hybrid Expand-only (concat as PRK, or one share as PRK and the
   other only in info) may meet the len≥HashLen limb for a uniform share but
   is non-standard — score under PQ1 (prefer concat-then-Extract).
- K4 — HKDF-Extract (or equivalent) salt is zero or static when IKM is
  low-entropy (password, PIN, user-chosen PSK), enabling multi-target
  attacks where one brute-force effort tests keys across all targets.
  High-entropy IKM (uniform keys, strong-group DH ss, IND-CCA2 KEM ss)
  may use a zero or fixed salt; for low-entropy IKM see also K3/K5.
- K5 — Password stretched with only a fast hash (no memory-hard or iterated KDF). Prefer Argon2id (or scrypt) for new designs; PBKDF2-HMAC-SHA-256+ with high iteration count only for legacy interop; bcrypt acceptable where already deployed.
- K6 — Bidirectional keys derived without per-direction domain separation (labels/context).
- K7 — Master secret used directly as application key.
- K8 — Cross-version KDF reuse.
- K9 — PRNG/RNG state reused across sessions without fresh entropy, or
  identical seed/personalization producing identical outputs.
- K10 — Non-contributory DH: peer forces a weak/known shared secret (small-order/identity share → total break). Yes if such a share is accepted or required validation is omitted (EC DH: PV1–PV4 / X25519–X448 all-zero; FF-DH: authentic (p,q,g), 1 < Y < p-1, and Y^q ≡ 1 mod p). PV5 is signature verification, not K10. Static-static DH is still contributory (both private keys affect ss) but gives no FS — F1/F2/A4, not K10. IND-CCA2 KEM: encapsulator randomness determines ss given pk — do not flag K10 (not a small-order force); static LT KEM PK is F1 for FS; hybrid strip/combiner → PQ1/PQ3.
- K11 — Missing key confirmation, confirmation only in one direction when mutual auth is claimed, confirmation MAC/tag over a wrong or incomplete transcript, session/connection identifiers used for authorization omitted from the confirmed transcript (session fixation), or application traffic / exporters / channel-binding tokens accepted or exposed under derived keys before required peer authentication/key confirmation completes (except intentional 0-RTT per R7/R7b). Deferred confirmation on the peer's first reply is acceptable for offline/async AKE; do not treat the session as mutually authenticated before that reply.
- K12 — SM3-based KDF in a GM/T profile that omits the mandated counter-mode structure (GB/T 32918.3 / GM/T 0003: KDF(Z,klen) = SM3(Z||ctr)‖… with 32-bit big-endian counter from 1). Do not require HMAC — the standard SM2 KDF is hash-counter, not HMAC-SM3. Flag ad-hoc substitutes (wrong counter encoding, missing Z binding, truncated/reordered blocks).
- K13 — GM/T-specified MAC (e.g., SM4-CBC-MAC) used without domain
  separation between MAC and encryption keys.

### Confidentiality / encryption
- C1 — Nonce reuse under the same key (AEAD). Catastrophic for non-MR AEADs
  (AES-GCM, AES-CCM, ChaCha20-Poly1305, XChaCha20-Poly1305, Ascon-AEAD128 —
  confidentiality + authenticity break); still a design defect for
  misuse-resistant AEADs (AES-GCM-SIV, AES-SIV) which only degrade more
  gracefully — do not design for reuse. Also: one-time MAC (Poly1305, bare
  GHASH) under a reusable/long-term key outside a standard AEAD (AES-GCM,
  ChaCha20-Poly1305, …) — do not use bare Poly1305/GHASH as a multi-message MAC.
- C2 — Unauthenticated encryption (no MAC/AEAD; e.g. CBC/CTR/stream alone);
  MAC-then-encrypt with CBC (padding-oracle / Vaudenay class); or
  Encrypt-and-MAC (MAC over plaintext only — not generically IND-CCA;
  deterministic MAC leaks plaintext equality). Prefer AEAD or Encrypt-then-MAC.
- C3 — Custom CBC + MAC composition: MAC and encryption keys not derived with
  distinct labels, or MAC-then-encrypt / custom padding specified where an AEAD
  would eliminate the padding-oracle class.
- C4 — ECB for structured/variable data.
- C5 — CTR with reused counter.
- C6 — Stream cipher with reused nonce.
- C7 — KEM decapsulation or ciphertext/public-key validation failure is distinguishable at the protocol level (explicit-rejection ⊥, distinct error codes/messages). Prefer implicit-rejection KEMs; explicit-rejection KEMs must treat rejections indistinguishably. Timing/side-channel distinguishability is out of scope (escalate to code-audit). See §2.4.
- C8 — Plaintext compression before encryption (CRIME / BREACH class).
- C9 — Length leakage via padding.
- C10 — Same key used for both directions: a single traffic or MAC key protects messages in both directions (distinct from K6).
- C11 — Nonce not guaranteed unique but non-misuse-resistant AEAD used.
- C12 — Online decryption / partitioning oracle: password- or low-entropy-
  key AEAD/encryption where attacker-controlled ciphertexts yield
  distinguishable success/failure, enabling offline partition of the key
  space (design-level; timing is out of scope).
- C13 — SM4 modes (CTR/OFB/CBC) reuse IV; SM4-GCM/GMAC-style composition
  not verified against the applicable national spec (GM/T 0069-2018 for
  SM4-GCM; GM/T 0024-2014 covers SM4-CBC + HMAC-SM3, not GCM).
- C14 — AEAD lacks key commitment: ciphertext can be crafted that
  decrypts to valid plaintext under multiple keys in multi-recipient
  settings. Nonce-misuse resistance ≠ key commitment (AES-GCM-SIV and
  AES-SIV are MR but not key-committing). AES-GCM, AES-GCM-SIV, AES-SIV
  (RFC 5297), AES-CCM, ChaCha20-Poly1305, XChaCha20-Poly1305, and
  Ascon-AEAD128 are not key-committing. Multi-key confusion is in scope by
  default whenever the same ciphertext is sealed to more than one key
  (group/sender-keys fan-out, multi-device copies, backup codes) — not only
  explicit group messaging; N/A for pairwise single-recipient channels
  unless the threat model states multi-key confusion. When in scope: No
  only if a committing AEAD or explicit commitment MAC is verified before
  plaintext use — `MAC(KDF(traffic_key, "commit"), ciphertext||AAD)` (or
  equivalent). AAD-only `H(key)` (or similar) is not sufficient under
  GCM-class multi-key attacks → Yes (finding), not No. Severity default:
  High when multi-recipient/fan-out is in scope (malicious sender breaks
  EA/INT via multi-key confusion); Low/Info only if multi-key confusion is
  explicitly out of scope.
- C15 — RSA-PKCS#1 v1.5 encryption: Bleichenbacher padding oracle
  (1998). Under repeated probing, plaintext recovers (ROBOT, 2017 vs
  TLS 1.2 RSA key exchange). Use RSA-OAEP (RFC 8017).
- C16 — MAC/AEAD authentication tag truncated below 128 bits without
  justification (online forgery cost ~2^{tag_bits}, e.g. 64-bit → ~2^64 queries;
  not a birthday bound). AES-GCM and ChaCha20-Poly1305 use 128-bit tags by
  design; AES-CCM short tags (e.g. TLS 1.2 CCM_8, RFC 7251) and legacy
  HMAC-*-96 need explicit threat-model justification. Severity default when
  unjustified: Medium for 64–96-bit tags; High if <64 bits.

### Forward / future / post-compromise
- F1 — No FS-capable ephemeral agreement: session secrets recoverable from long-term decryption keys alone (static RSA key transport; encaps to a long-term KEM PK with no ephemeral KEM/DH contribution; static-static DH). A fresh random sealed under an LT public key is not FS — LT compromise decrypts all past sessions (see also F8). Semi-static prekeys (signed prekeys, reusable KEM PKs) without rotation/lifetime bound: Medium when FS is claimed (weakened FS — prekey compromise degrades FS for sessions that depended on it; reusable KEM prekey sk decrypts all encaps to that PK; multi-DH handshakes may need more than the prekey alone); still require per-session ephemerals (EK/OPK-class). Lifetime is qualitative (bound + rotation exist vs not) — do not invent a day/week heuristic. Finding severity Medium; coverage-matrix Enforced=Partial for that FS limb only (Partial is matrix-only, never a finding severity).
- F2 — Static DH claimed to provide FS (static keys do not provide FS; key rotation protects future sessions only — past sessions using old static keys remain exposed).
- F3 — Continuous messaging without a ratchet (all messages under static
  session keys only). N/A for request/response or single-session protocols
  whose FS comes from handshake ephemerals (F1/F8); per-message DH is not
  required there. Mid-session KeyUpdate-class rekey is RD6, not F3.
- F4 — Symmetric-only ratchet (no DH ratchet) in continuous messaging: after
  state compromise the attacker derives all future keys — no PCS against
  full-state compromise and no FUT (healing). N/A when PCS/FUT is not claimed
  and the protocol is request/response with handshake-ephemeral FS only;
  KeyUpdate-class rekey is RD6, not a messaging DH ratchet.
- F5 — Long-term key directly encrypts session traffic.
- F6 — No PQ / no hybrid for long-term confidentiality, or HNDL claimed
  with a weak path. Unclaimed HNDL → Low/Info. When HNDL / long-term PQ
  confidentiality is claimed: require a non-strippable PQ or hybrid KEM
  path (classic-only must not remain silently selectable — PQ3), AEAD keys
  matching the claim, and KEM parameters matching the claim. Defaults when
  the HNDL claim is silent/generic: AEAD at ≥256-bit strength (AES-256-GCM/
  CCM/GCM-SIV, AES-SIV-512, ChaCha20-Poly1305/XChaCha20-Poly1305; any
  128-bit-key AEAD is Partial — AES-128-*, AES-SIV-256, Ascon-AEAD128, SM4-*
  — RFC 5297 AES-SIV-N numbers total SIV key bits, not AES strength; prefer
  256-bit-strength AEAD for multi-target margin and conservative PQ sizing;
  Grover does not make AES-128 a practical break under NIST category-1
  budgeting)
  and KEM category 3+ (e.g. ML-KEM-768+). Explicit NIST category-1 /
  AES-128-equivalent HNDL claim → ML-KEM-512 and 128-bit AEAD keys OK.
   Severity: Critical if the non-strippable PQ/hybrid path is absent or
   classic-only remains silently selectable (PQ3); Medium if hybrid/PQ is
   present and non-strippable but, under a generic/higher HNDL claim,
   traffic keys are 128-bit (AES-128-*/AES-SIV-256/Ascon/SM4) or the KEM is
   category-1-only. Hybrid **combiner** defects (PQ1 (a)–(e)): score under
    PQ1 only — do not also raise a separate F6 finding; cite HNDL as an
    affected goal on the PQ1 finding. Under HNDL: PQ1 either-share failure
    ((b); (a) concat/single-share as traffic key) is Critical; PQ1 (a)
    raw-XOR-without-KDF and (c)(d)(e) are High (either-share may hold;
    non-standard/incomplete combiner — not a second F6 Critical).
   Classical-only
   signatures are not HNDL (confidentiality). Post-CRQC authentication: if
   claimed, require non-strippable PQ/hybrid auth (PQ3 — dual/hybrid
   signatures or composite certs must not accept classic-only); if
   unclaimed, classic-only sigs → Low/Info only.
   Pure-PSK/ticket resumption: not auto-Critical under F6 when the
   establishing handshake was non-strippable hybrid/PQ and the resumption
   secret (PSK or ticket-carried key schedule input) is derived from that
   hybrid secret (inherits HNDL); still apply F6 AEAD sizing to resumed
   traffic keys. Critical F6 if pure-PSK is fed only by classic-only
   establishment or PQ is strippable (PQ3). Ticket sealing-key compromise
   (unwrap of PSK or of sealed traffic keys) is F8 / R8 — do not re-score
   F6 HNDL from sealing-key exposure alone when the sealed secret was
   hybrid-derived; external/provisioned PSKs do not inherit hybrid HNDL.
   FS of pure-PSK modes is F8, not F6; bind resumption KE mode including
   hybrid (R8).
- F7 — Long-term key confined to HSM/hardware but used such that sessions
  have no FS ephemeral contribution and no rotation/revocation plan (HSM
  custody alone is not FS — see F1, REV1).
- F8 — Early-data keys, or pure-PSK resumption keys, derived without a fresh handshake ephemeral in those keys' schedule (no FS against PSK/ticket compromise). A DHE that contributes only to main-handshake keys (e.g. TLS 1.3 `psk_dhe_ke`) does not protect already-sent early data. "Ephemeral" here means a contribution not recoverable from long-term decryption keys alone (deleted DH/KEM ephemeral private key); a fresh random sealed under an LT KEM/RSA key is F1, not an FS ephemeral. N/A for an intentional pure-PSK (non-FS) resumption mode when FS is not claimed for that mode; Yes when FS is claimed for resumed/early-data sessions, or when pure-PSK is the only resumption path and the protocol class implies handshake-ephemeral FS for all sessions. HNDL of pure-PSK after hybrid establishment is F6 (inheritance), not F8.
- F9 — No PCS/FUT recovery mechanism: no in-band self-healing (DH/PQ ratchet,
  tree update, component refresh) or out-of-band recovery (revocation +
  reissue) after key exposure. Symmetric KeyUpdate-class rekey alone is not
  PCS recovery (see F4, RD6). N/A when PCS/FUT is not claimed (typical
  request/response or single-session protocols with handshake-ephemeral FS).

### Point validation / EC
- PV1 — EC point not verified on-curve → invalid-curve attack; attacker
  can choose weak curve parameters and forge signatures or derive bits
  of the static private key.
- PV2 — Small-order or identity point accepted in DH → total break. For X25519/X448, verify the shared secret is not the all-zero value after DH.
- PV3 — Compressed point decoded without on-curve validation → invalid-point oracle.
- PV4 — Cofactor not cleared/checked in ECDH → small-subgroup / torsion-point attack; for X25519/X448 rely on the all-zero check (PV2).
- PV5 — ECDSA point not verified before signature verification → signature forgery.

### Signatures
- S1 — RSA-PKCS#1 v1.5 used for new protocol signatures (prefer RSA-PSS);
  or signature verification that accepts incomplete/non-DER padding
  (Bleichenbacher 2006 forgery class). N/A for verifying already-issued
  PKI certificates that use PKCS#1 v1.5 with full padding checks.
- S2 — ECDSA with biased, predictable, non-uniform, or reused nonces (same k on two messages → full private-key recovery; prefer RFC 6979 or FIPS 186-5 deterministic). N/A for deterministic EdDSA (Ed25519/Ed448) when nonces follow RFC 8032.
- S3 — Ed25519/Ed448 without domain separation where needed (use Ed25519ctx or Ed448 with a non-empty protocol context per RFC 8032; Ed25519ph/Ed448ph with context for prehash; or separate key pairs per protocol).
- S4 — Signature applied to raw message instead of a collision-resistant hash (mainly RSA/legacy schemes that sign unhashed or ad-hoc-hashed input). N/A for schemes that hash internally as specified (EdDSA, RSA-PSS, ML-DSA, SLH-DSA, ECDSA with a named SHA-2/SHA-3 hash).
- S5 — Signature excludes part of the transcript.
- S6 — No domain separation between signature purposes.
- S7 — Rogue key / key substitution: signature also verifies under an
  alternate public key not bound to the claimed identity (missing
  key↔identity binding in cert or transcript).
- S8 — SM2 signature used outside its mandated GM/T profile; Z_A/user-ID
  binding missing or ignored (GM/T 0009 §5.1).
- S9 — SM2 key format confused with X9.62/X9.63 EC key; parameter-set mismatch enables cross-protocol attack.
- S10 — ML-DSA / SLH-DSA signature context string (`ctx`) reused across protocol operations, or omitted where cross-protocol/purpose domain separation is required (FIPS 204 / FIPS 205).

### Negotiation / downgrade
- N1 — Cipher suite offer list and selected cipher/AEAD not both in the
  authenticated transcript (MITM can strip strong offers or substitute
  selection — FREAK-class). "Present in a cleartext hello" alone is not
  commitment.
- N2 — Group/curve/KEM offer list and selected group not both in the
  authenticated transcript (Logjam-class).
- N3 — Version offer and selected version not both in the authenticated
  transcript (version rollback).
- N4 — Security-relevant extensions (and their acceptance/rejection) not
  in the authenticated transcript (extension strip/inject).
- N5 — Negotiation response ambiguous: multiple acceptable answers possible without deterministic tiebreak.
- N6 — No hello-retry-equivalent on mismatch, or hello-retry cookie/token
  not bound to the ClientHello/transcript (unbound retry enables parameter
  substitution or amplification); or datagram/UDP server issues a large
  response before address validation (cookie/retry), enabling amplification.
- N7 — Algorithm agility without deprecation path; or disallowed/deprecated
  algorithms remain offerable or acceptable when a secure alternative is
  defined (e.g. 64-bit-block ciphers still in a VPN/IPsec proposal set).

### Randomness / nonce
- RD1 — Predictable session ID used as a secret (auth token, key lookup that
  grants access without further proof). N/A if the ID is only a public handle
  (connection ID) and authorization uses separate key material.
- RD2 — Time-based value used as AEAD/cipher nonce or key material (clock
  skew/predictability → reuse or precomputation). N/A for timestamps used only
  as anti-replay freshness under a MAC/AEAD.
- RD3 — Counter not monotonic across crashes.
- RD4 — Nonce/IV predictable under the same key (precomputation or
  offline guessing). Reuse under the same key → C1/C11, not RD4 alone.
- RD5 — RNG seeded from low-entropy source.
- RD6 — No rekey / lifetime cap, or rekey messages not authenticated under the current traffic keys (mid-session KeyUpdate-class auth; distinct from handshake key confirmation K11).
- RD7 — Nonce space too small, or random nonces used without a rekey bound
  at or below the collision limit. For random 96-bit nonces (AES-GCM,
  ChaCha20-Poly1305): ≤ 2^32 messages per key (SP 800-38D-class; birthday
  ~2^48 is not the design limit — do not use birthday as the cap). AES-GCM
  with IV length ≠ 96 bits uses the general IV construction — ≤ 2^32
  invocations per key (SP 800-38D); prefer 96-bit IVs. Counter/sequence
  nonces need only uniqueness + rekey before wrap. XChaCha20-Poly1305
  (192-bit) random nonces have a far higher collision bound but still need
  a key-lifetime volume cap. Misuse-resistant AEAD (AES-GCM-SIV, AES-SIV)
  does not lift the volume/rekey requirement and does not justify designing
  for nonce reuse (C1): still rekey well below the birthday bound on the
  nonce/synthetic-IV space; do not relax the 2^32 cap for AES-GCM or
  ChaCha20-Poly1305. Also flag AEAD per-message length limits (AES-GCM:
  ≤2^36−32 bytes/plaintext per SP 800-38D; ChaCha20: 2^32 blocks/msg).

### Post-quantum
- PQ1 — Hybrid combiner is weak. Prefer HKDF-Extract / SP 800-56C with both
   shares as IKM and/or salt (concat-then-Extract default), or equal-length
   OTP-style XOR of the two shares (or of two equal-length hashes) then
   domain-separated KDF/Extract — not raw XOR as the traffic key (if lengths
   differ, hash each to a common length first). Dual-PRF means Extract(salt,
   IKM) with either input high-entropy secret (e.g. salt=ss1, IKM=ss2) — that
   is the standard either-share argument; do not call Expand a dual-PRF.
   Yes if: (a) shares used as session/traffic keys without a KDF — raw concat
   or a single share as the working key (either-share KS fails when the broken
   share alone determines usable key bits, e.g. prefix truncation to
   ss_classic); or raw equal-length XOR as the traffic key without a
   subsequent domain-separated KDF/Extract (either-share may hold; still a
   defect: no multi-key/domain separation, and DH ss is non-uniform so
   XOR-then-use skips Extract); (b) one share never enters the key schedule
   (omitted, or only in AEAD AAD/fixed labels) — either-share KS fails when
   that share is the broken one; (c) HKDF-Expand-only on raw
   `ss_classic||ss_pq` (concat is not a PRK — always Extract first; sole
   IND-CCA2 KEM ss may Expand-only only per K3); (d) Expand with only one
   share as PRK and the other only in info (non-SP-800-56C; not dual-PRF
   Extract — standard PRF either-share holds only when the secret share is
   the PRK; when only the info share is secret, security needs a non-standard
   known-key/OW argument — require an explicit combiner proof; often lacks
   binding/robustness; no auto-No from a named profile alone); or (e) any
   other non-default combiner (e.g. nested cascade KDF(ss1, KDF(ss2))) without
   an explicit security argument. No if concat-then-Extract / SP 800-56C,
   equal-length XOR-then-KDF/Extract, or a non-default combiner has a proof.
   N/A if no hybrid. Severity when Yes: Under hybrid/HNDL claim — Critical if
   either-share KS fails by construction ((b); (a) concat/single-share as
   traffic key); High if either-share can still hold but the combiner is
   incomplete or non-standard ((a) raw XOR-without-KDF; (c)(d)(e)). Without
   that claim — High for either-share fails ((b); (a) concat/single-share);
   Medium for (a) XOR-without-KDF and (c)(d)(e). Do not also emit a separate
   F6 row for the same combiner defect — list F6 only as an affected goal when
   HNDL is claimed (see F6 scoring ownership).
- PQ2 — KEM public key not authenticated (no signature or transcript binding
  of the recipient/encaps KEM PK to peer identity). Active PK substitution
  lets a MITM own the PQ share: hybrid either-share still hides KS via the
  classic share at handshake time, but that MITM later breaks HNDL for the
  session once classic falls (they already hold ss_pq). Pure-PQ (no classic
  share) → full MITM KS break. Offline/async prekey: authenticate under the
  identity key (PQXDH-class) or equivalent. Severity: Critical if pure-PQ and
  substitution is undetectable; High under hybrid/HNDL claim (active path
  only — not passive strip; PQ3 owns silent classic-only); Medium if hybrid
  path exists without HNDL claim; N/A if no KEM. Do not stack a separate PQ3
  row for the same missing PK auth.
- PQ3 — PQ KEM share or PQ authentication artifact (dual/hybrid
  signature, composite cert) can be stripped or omitted without detection,
  or a classic-only path remains negotiable without detection when
  hybrid/PQ was offered — allowing classic-only fallback. Under an HNDL
  claim: single Critical finding with Pattern IDs PQ3,F6 (path absent/
  strippable — not a combiner issue). Under claimed post-CRQC
  authentication, silent classic-only acceptance is Critical (auth limb).
- PQ4 — PQ ciphertext not bound to the session transcript (or equivalent
  session-unique context). Unbound CT enables cross-session replay/mix of the
  KEM share (cf. R2). Severity: High when unbound; N/A if no KEM.

### Group / multi-party
- GP1 — Sender key not bound to group membership (non-member can inject
  under a key the group accepts).
- GP2 — Membership change does not update group key.
- GP3 — No authenticated group epoch/membership transcript (or equivalent)
  so members can hold a silent split-view / partition without detection.
- GP4 — Removed member retains decryption ability after the epoch that
  should exclude them (cf. GP2).
- GP5 — Group creator controls all keys (no contributory). N/A if an
  intentional sender-keys (or other non-contributory) design matches the
  threat model.

### Metadata / traffic analysis
- M1 — Unencrypted metadata leaks identity/membership/presence (when ANO or
  identity-hiding is claimed, also count cleartext long-term public keys or
  certificates, and cleartext PSK/ticket/resumption identity hints that
  re-identify the user across sessions). N/A for ordinary server-auth
  protocols that do not claim anonymity.
- M2 — Message size/timing leaks message content. N/A when neither
  anonymity nor content-hiding / traffic-analysis resistance is claimed
  (ordinary request/response channels); Yes when claimed, or when
  size/timing is the only separator for a high-value secret (e.g. password
  length in a PAKE).
- M3 — No padding/traffic-shaping; size/timing patterns enable
  fingerprinting or traffic analysis. N/A under the same conditions as M2.
- M4 — After traffic keys exist: alerts unencrypted or alert type
  distinguishable (e.g. close_notify vs bad_record_mac oracle); or clean
  shutdown lacks a cryptographic end-of-stream signal so a network adversary
  can truncate without detection. Pre-handshake errors with no application
  data: N/A for the encryption limb. Truncation limb N/A for pure
  datagram/message protocols with no ordered stream or clean-shutdown claim;
  still flag encrypted-alert oracles when an alert channel exists.

### Modern frameworks (Noise / HPKE)
- MF1 — Noise pattern chosen does not match required authentication or
  forward-secrecy level (e.g., `Noise_NN` provides no authentication at all;
  static-key compromise enables impersonation in patterns that rely
  on the static key for peer authentication but does not necessarily
  break FS if ephemeral keys were fresh and deleted).
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
- P3b — No client puzzle / proof-of-work; DoS-gating on session establishment is
  absent. N/A if DoS is out of the threat model or not a PAKE/session-setup
  concern. P3b does not replace anti-replay (cf. R7/R7b/R8).

### Revocation / recovery
- REV1 — No key revocation mechanism. N/A for single-session / no long-lived
  device identity, or when LT identity is external PKI with an accepted
  external revocation path (CRL/OCSP/etc.); flag multi-device or long-lived
  identity with neither in-protocol exclusion nor referenced external path.
- REV2 — Compromised device cannot be excluded. N/A when there is no
  multi-device/multi-endpoint identity model; else requires membership/epoch
  update or revocation (cf. GP2, GP4, F9).

### Encoding / wire format
- E1 — Ambiguous length fields or duplicate fields parsed inconsistently
  across implementations, enabling transcript manipulation.

### Deniability
- DEN1 — Non-repudiable signatures break deniability. N/A if deniability
  is not claimed.
- DEN2 — Online vs offline deniability mismatch. N/A if deniability is
  not claimed.

### Design smells
- I1 — Length-extension on full-output Merkle-Damgård hashes (SHA-256,
  SHA-512, SM3) when used as a naked MAC/KDF (use HMAC/KMAC, or a hash
  natively LE-resistant: SHA-3, BLAKE2, BLAKE3). Truncated SHA-2 (SHA-384,
  SHA-512/256) resists classic LE from the truncated digest alone; still
  prefer HMAC/KMAC for MAC constructions.
- I2 — Asymmetric encrypt-and-sign (or sign-then-encrypt) without binding
  signature to ciphertext and intended recipient/identity → surreptitious
  forwarding or recipient substitution (signature strips/rewraps under a
  different cover key).
- I3 — Custom padding scheme where AEAD would have removed the
  oracle (Vaudenay 2002 padding-oracle class).
- I4 — Password used as direct key.
- I5 — No protocol versioning at all.
- I6 — Mobility mishandled: session bound to network location (IP/VPN)
  breaks on path change; OR session migrates to a new path/address without
  proving the peer owns the new path (injection/hijack after migration).
- I7 — Session-state mode confusion: 0-RTT, abbreviated resumption, external
  PSK vs resumption PSK, full handshake, post-handshake auth, and rekey are
  not clearly distinguished in the state machine or transcript (labels,
  binders, or accepted message types), allowing replay, downgrade, or
  coercion between modes; or the handshake accepts unexpected message types,
  wrong-epoch messages, or silent state skips (jumps to application-data /
  exporter exposure without the required prior messages) — datagram reordering
  of concurrent expected-flight messages is not I7; or mid-session
  re-handshake/renegotiation omits a cryptographic binder to the prior
  session from the new handshake's authenticated transcript —
  renegotiation-splice class. Acceptable binder forms (any one): prior
  Finished, session-hash over the prior full handshake, or exporter/
  channel-binding value derived from that transcript **after** required peer
  authentication/key confirmation (not 0-RTT/early-secret exporters that omit
  Finished/peer confirmation — A3/K11) — each must cover the prior session's
  authenticated identities and client-auth status; no single wire form is
  preferred. "Any authenticated link" or a bare connection ID without that
  binder is insufficient. Key-install re-acceptance that resets nonces under
  live traffic keys is R1, not I7.

---

## 4. Output Format — `findings.md`

**Mandatory disclaimer.** Every `findings.md` (and any consolidated
review report) MUST include the full `## ⚠️ Important Limitations`
section from the skill front-matter (same heading, bullets, production
warning, and Aumasson quote) **verbatim** immediately after Scope/Source
and before Summary. Do not shorten, paraphrase, omit the emoji heading,
drop the quote, or replace it with a one-line note. A report without this
full block is incomplete.

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
Verdict: FAIL if any Critical or High; PASS-WITH-FIXES if Medium only; PASS if Low/Info only (or none)

## Goals, Threat Model, Invariants, Primitives, Proof Strategy
See goals.md, threat-model.md, handshake-flow.md, state-machine.md,
invariants.md, naming.md, primitives.md, proof-sketch.md.

## Findings

### F-001 — <title>
- **Severity:** Critical
- **Pattern IDs:** A1, K2
- **Location:** Step 4; `master_secret = SHA256(...)`
- **Description:** ...
- **Attacker scenario:** ...
- **Affected goals:** FS, KS
- **References:** standard, paper, or CVE if known — do not invent CVEs or citations
- **Fix:** ...

## Coverage Matrix
Required rows: KS, IND, INT, EA, MA, KA, FS, PCS, FUT, HNDL, DEN, ANO,
REPLAY, DG, KCI, UKS, BIND, FR, classical-param-strength (default 128-bit
when silent per §2.8). Enforced: Yes / Partial / No / N/A.
Confidence: High (mechanism in spec) / Medium (informal) / Low (claimed only).
HNDL: Yes = non-strippable PQ/hybrid + AEAD/KEM match claim (F6 defaults if
generic); Partial = hybrid present but under-strength for generic/higher
claim (AEAD/KEM sizing) **or** PQ1 incomplete/non-standard combiner under
HNDL where either-share may still hold ((a) XOR-without-KDF; (c)(d)(e));
No = classic-only / strippable when HNDL claimed, or PQ1 either-share fail
((b); (a) concat/single-share as traffic key); N/A = not a goal. Pure-PSK
after hybrid establishment inherits HNDL via PSK (F6) — not auto-No.
Combiner defects → PQ1 finding (not a second F6 row). Notes: state generic
vs explicit category.

| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|

## Catalog Checklist
Every §3 pattern → Yes (→ Finding F-xxx) / No / N/A + one-line reason.
```

---

## 5. Brief Protocol Notes

- **TLS 1.3** — downgrade protected by `supported_versions` + transcript + downgrade random; 0-RTT replayable by design and early-data keys PSK-bound (no FS vs PSK compromise even under `psk_dhe_ke`). ECDHE requires the all-zero shared-secret check for X25519/X448. Standalone ML-KEM key agreement is OPTIONAL via draft-ietf-tls-mlkem; the ECDHE+ML-KEM hybrid is OPTIONAL via draft-ietf-tls-ecdhe-mlkem. Without a PQ key-agreement mechanism, long-term confidentiality is vulnerable to harvest-now/decrypt-later (HNDL). If HNDL is a goal: require non-strippable PQ or hybrid KEM and size AEAD/ML-KEM per F6 (generic → AES-256/ChaCha20 + ML-KEM-768+; explicit cat-1 → AES-128 + ML-KEM-512 OK).
- **X3DH → PQXDH** — PQXDH combines X25519 (3–4 DH outputs in the classic X3DH set: identity×SPK, ephemeral×IK, ephemeral×SPK, optional ephemeral×OPK) with an ML-KEM shared secret via HKDF. The HKDF info label is a fixed, protocol-versioned string that MUST be domain-separated from X3DH; verify the exact label against the target spec. Both the X25519 DH shared secrets and the ML-KEM ss must enter the same KDF/combiner (PQ1) so neither alone yields the session key — a MITM who strips the PQ share must not be able to force an undetected classical-only X3DH (PQ3). Additionally: authenticate PQ public key under identity key (PQ2), bind PQ ciphertext to the handshake transcript (PQ4).
- **OTRv3 / OTRv4** — Off-the-Record messaging protocols built for deniability and forward secrecy. OTRv3 uses an online AKE + Socialist Millionaire Protocol for authentication, and conceals public keys from network observers. OTRv4 adds offline/online handshakes and a double-ratchet-like messaging layer, but dropped public-key concealment; verify the handshake model and deniability claims against the target spec.
- **vault1317** — Signal-inspired protocol that adds ring-signature-based deniability and public-key/metadata concealment. Review ring-signature member binding, handshake identity hiding, and leakage through handshake timing/size.

---

## 6. References

**IETF / RFCs:**
- TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446
- HPKE: https://www.rfc-editor.org/rfc/rfc9180
- HKDF: https://www.rfc-editor.org/rfc/rfc5869
- BLAKE2: https://www.rfc-editor.org/rfc/rfc7693
- AES-GCM-SIV: https://www.rfc-editor.org/rfc/rfc8452
- PKCS#1 v2.2 (RSA-PSS/OAEP): https://www.rfc-editor.org/rfc/rfc8017
- MLS: https://www.rfc-editor.org/rfc/rfc9420
- Ed25519/Ed448: https://www.rfc-editor.org/rfc/rfc8032
- X25519/X448: https://www.rfc-editor.org/rfc/rfc7748
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
- FIPS 186-5 (DSS/ECDSA/EdDSA): https://csrc.nist.gov/pubs/fips/186-5/final
- FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
- FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- FIPS 205 (SLH-DSA): https://csrc.nist.gov/pubs/fips/205/final
- SP 800-56A Rev. 3 (key establishment): https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
- SP 800-56C Rev. 2 (KDF): https://csrc.nist.gov/pubs/sp/800/56/c/r2/final
- SP 800-57 Part 1 Rev. 5 (key management recommendations): https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- SP 800-131A Rev. 2 (algorithm transitions): https://csrc.nist.gov/pubs/sp/800/131/a/r2/final
- SP 800-38B (CMAC): https://csrc.nist.gov/pubs/sp/800/38/b/final
- SP 800-38D (AES-GCM): https://csrc.nist.gov/pubs/sp/800/38/d/final
- SP 800-108 Rev. 1 (KDF in Counter/Feedback/DPI mode): https://csrc.nist.gov/pubs/sp/800/108/r1/final
- FIPS 202 (SHA-3/SHAKE): https://csrc.nist.gov/pubs/fips/202/final
- SP 800-185 (KMAC/cSHAKE): https://csrc.nist.gov/pubs/sp/800/185/final
- SP 800-208 (LMS/XMSS): https://csrc.nist.gov/pubs/sp/800/208/final
- SP 800-227 (KEM recommendations): https://csrc.nist.gov/pubs/sp/800/227/final
- SP 800-232 (Ascon-Based Lightweight Cryptography): https://csrc.nist.gov/pubs/sp/800/232/final

**Chinese crypto (GM/T series — not freely online; cite by standard number):**
- GM/T 0009-2012 (SM2 digital signature algorithm)
- GM/T 0024-2014 (SSL/TLS protocol using SM2/SM3/SM4)
- GM/T 0069-2018 (SM4-GCM authenticated encryption)

**Analysis tools:**
- ProVerif: https://proverif.inria.fr/
- Tamarin: https://tamarin-prover.github.io/
- Verifpal: https://verifpal.com/

**Attacks:** Bleichenbacher, ROBOT, FREAK/Logjam, KRACK, Triple Handshake.
