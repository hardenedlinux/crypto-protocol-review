# Crypto Protocol Review

**Do not roll your own crypto.** Unless you are a cryptography engineer with peer-reviewed expertise, use audited standards. This project is a review aid, not a replacement for expert review.

## Overview

This project provides a structured methodology for reviewing cryptographic protocol designs at the specification level. `SKILL.md` defines a 10-step review pipeline covering handshake flows, key derivation, threat models, state machines, negotiation, binding, primitive selection, and attack-pattern checks.

## Important Limitations

AI-generated reviews can miss critical vulnerabilities, especially in cryptography.

This project helps reviewers:

- Reduce initial review workload
- Apply a consistent checklist
- Identify common protocol-level attack patterns

It does not replace:

- Expert cryptography engineering review
- Formal verification with tools such as ProVerif or Tamarin
- Implementation audit for side channels, constant-time behavior, RNG internals, or memory safety
- Peer-reviewed protocol and primitive design

## SKILL.md Usage

The skill is designed for protocol design review, not implementation review.

### When to Use

- Reviewing a protocol handshake design
- Auditing protocol-level security claims
- Comparing protocol variants
- Finding downgrade, replay, key-binding, or negotiation issues

### Pipeline

```text
spec-extractor -> protocol-model.json
security-goal-extractor -> goals.md
threat-model-builder -> threat-model.md
handshake-analyzer -> handshake-flow.md
state-machine-auditor -> state-machine.md
invariant-checker -> invariants.md
naming-binding-auditor -> naming.md
primitive-selector -> primitives.md
proof-strategy-checker -> proof-sketch.md
attack-pattern-checker -> findings.md
```

Cross-reference findings against `SKILL.md` §3 and assign severity using the rubric in §2.10.

## Review Scope

| In Scope | Out of Scope |
|----------|--------------|
| Handshake flows | Constant-time code |
| Key derivation | Side channels |
| Primitive selection | RNG internals |
| Authentication and identity binding | Library CVEs |
| FS/PCS/HNDL claims | Named implementation configuration audits |
| Replay/downgrade resistance | Memory safety |
| State machines | Fuzzing |

## Directory Structure

```text
flaw-examples/          # Legacy or flawed specifications used for validation
  ssl3_rfc6101.txt
  tls12_rfc5246.txt
  tls1compression.txt
  ipsec_esp.txt
  ipsec_ah.txt
  ipsec_hmac.txt
  ipsec_ah_esp.txt
  dh_key_agreement.txt
  arpitools.txt        # RFC 5247 EAP Key Management Framework
review/                 # Cleaned review reports
  SUMMARY.md
  ssl3_review.md
  tls12_review.md
  tlscompression_review.md
  ipsec_esp_review.md
  ipsec_ah_review.md
  hmac_sha1_96_review.md
  ipsec_overview_review.md
  dh_review.md
  arp_review.md         # Reviews arpitools.txt/RFC 5247; filename retained
```

## Validated Examples

| Source | Protocol | Verdict | Main issues |
|--------|----------|---------|-------------|
| `ssl3_rfc6101.txt` | SSL 3.0 | FAIL | POODLE/CBC MtE, RSA-PKCS#1 v1.5, weak/export suites |
| `tls12_rfc5246.txt` | TLS 1.2 | FAIL | RSA/static suites, CBC MtE, renegotiation/resumption binding gaps |
| `tls1compression.txt` | TLS Compression | FAIL | Compression before encryption |
| `ipsec_esp.txt` | IPsec ESP | FAIL | Encryption without auth, legacy algorithms, optional anti-replay |
| `ipsec_ah.txt` | IPsec AH | PASS-WITH-FIXES | 96-bit ICVs, legacy MACs, optional anti-replay |
| `ipsec_hmac.txt` | HMAC-SHA-1-96 | PASS-WITH-FIXES | 96-bit tag and SHA-1 legacy profile |
| `ipsec_ah_esp.txt` | ESP NULL | PASS-WITH-FIXES | No confidentiality by design; requires strong auth |
| `dh_key_agreement.txt` | RFC 2631 DH | FAIL | Optional validation, weak params, SHA-1 KDF, static-static mode |
| `arpitools.txt` | EAP Key Management | FAIL / conditional | RADIUS MD5, channel binding, AAA key transport, freshness dependencies |

## What Remains for Human Auditors

Human experts must still verify:

1. Cryptographic proof correctness
2. Implementation-specific side channels
3. Constant-time behavior
4. Formal verification models
5. Edge-case state handling
6. Attack variants not in the catalog
7. Primitive composition and cross-protocol interactions
8. Regulatory and deployment-specific requirements

## Security Auditing Is Not Complete Without

- [ ] Peer review by cryptographers with domain expertise
- [ ] Formal methods verification
- [ ] Reference implementation audit
- [ ] Fuzzing against implementations
- [ ] Deployment and configuration review
- [ ] Incident response planning

## References

- RFC 8446 (TLS 1.3), RFC 9180 (HPKE), RFC 9420 (MLS)
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- Signal X3DH and PQXDH
- Attacks: Bleichenbacher, POODLE, CRIME/BREACH, ROBOT, FREAK/Logjam, KRACK, Triple Handshake

**Last updated:** July 2026
