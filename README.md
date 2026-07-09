# Crypto Protocol Review

**DO NOT ROLL YOUR OWN FUCKING CRYPTO.**
Unless you are a cryptography engineer with peer-reviewed credentials, use audited standards. This tool is a reference, not a replacement for expert review.

---

## Overview

This project provides a structured methodology for reviewing cryptographic protocol designs at the specification level. The `SKILL.md` defines a 10-step review pipeline covering handshake flows, key derivation, threat models, state machines, and attack pattern catalogs.

## ⚠️ Important Limitations

**AI-generated reviews can miss critical vulnerabilities, especially in cryptography.**

This tool is designed to:
- Help security auditors reduce initial review workload
- Provide structured checklist coverage
- Identify common attack patterns

**This tool does NOT replace:**
- Expert cryptography engineering review
- Formal verification (ProVerif, Tamarin)
- Implementation security audit (constant-time, side channels)
- Peer-reviewed cryptographic primitives

**Cryptography engineering is serious.** Missteps lead to:
- Catastrophic breaks (POODLE, Heartbleed, FREAK)
- National-security-grade vulnerabilities
- Irreversible data exposure

**When in doubt, consult experts. When shipping, use standards with 10+ years of scrutiny.**

---

## SKILL.md Usage

The skill is designed for reviewing protocol designs (not implementations).

### When to Use

- Reviewing a new protocol handshake design
- Auditing protocol-level security claims
- Comparing protocol variants (TLS 1.2 vs 1.3, X3DH vs PQXDH)
- Finding downgrade/pathway issues in protocol negotiation

### How to Use

1. Load `SKILL.md` into your review session
2. Follow the 10-step pipeline:
   ```
   spec-extractor → protocol-model.json
   security-goal-extractor → goals.md
   threat-model-builder → threat-model.md
   handshake-analyzer → handshake-flow.md
   state-machine-auditor → state-machine.md
   invariant-checker → invariants.md
   naming-binding-auditor → naming.md
   primitive-selector → primitives.md
   proof-strategy-checker → proof-sketch.md
   attack-pattern-checker → findings.md
   ```
3. Cross-reference findings against the attack catalog (§3)
4. Assign severity (Critical/High/Medium/Low/Info)

### Review Scope

| In Scope | Out of Scope |
|----------|--------------|
| Handshake flows | Constant-time code |
| Key derivation | Side channels |
| Primitive selection | RNG internals |
| Authentication binding | Library CVEs |
| FS/PCS/HNDL | Implementation bugs |
| Replay/downgrade | Named implementation configs |
| State machines | |

---

## Directory Structure

```
flaw-examples/          # Known vulnerable protocols for validation
  ssl3_rfc6101.txt      # POODLE-vulnerable SSL 3.0
  tls12_rfc5246.txt     # TLS 1.2 (BEAST, Lucky13)
  tls1compression.txt    # CRIME/BREACH
  ipsec_esp.txt         # Bit-flipping vulnerabilities
  dh_key_agreement.txt   # Small subgroup attack
  ...
review/                 # Validated review reports
  SUMMARY.md            # Validation results
  ssl3_review.md
  tls12_review.md
  ...
```

---

## Validated Protocols

| Protocol | Verdict | Critical Issues |
|----------|---------|-----------------|
| SSL 3.0 | FAIL | MAC-then-encrypt, version rollback |
| TLS 1.2 | FAIL | BEAST, Lucky13, Bleichenbacher |
| TLS Compression | FAIL | CRIME/BREACH |
| IPsec ESP | FAIL | Bit-flipping, no authentication |
| Diffie-Hellman | FAIL | Small subgroup attack |
| ARP | FAIL | No authentication |

---

## What Remains for Human Auditors

Even with automated review, human experts must verify:

1. **Cryptographic proof correctness** - Reduction targets, assumptions, ideal-model usage
2. **Implementation-specific side channels** - Timing attacks on decryption, branch prediction
3. **Constant-time verification** - Memory access patterns, secret-dependent branches
4. **Formal verification** - ProVerif/Tamarin models match the spec
5. **Edge cases** - Protocol state confusion, error handling, reconnection races
6. **New attack variants** - Attack patterns not yet in catalog
7. **Primitive combinations** - Cross-protocol interactions, composition issues
8. **Regulatory compliance** - FIPS 140-3, EMV, payment network requirements

---

## Security Auditing Is Not Complete Without

- [ ] Peer review by cryptographers with domain expertise
- [ ] Formal methods verification
- [ ] Reference implementation audit
- [ ] Fuzzing against the implementation
- [ ] Real-world deployment testing
- [ ] Incident response planning

---

## References

- RFC 8446 (TLS 1.3), RFC 9180 (HPKE), RFC 9420 (MLS)
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- Signal: X3DH, PQXDH
- Attacks: Bleichenbacher (1998), ROBOT (2017), FREAK/Logjam, KRACK, Triple Handshake

---

**Last updated:** July 2026
