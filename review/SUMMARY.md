# SKILL.md Validation — Flaw Examples Review Summary

**Review date:** 2026-07-11  
**Skill:** crypto-protocol-review (`SKILL.md`)  
**Sources:** `flaw-examples/*`  
**Reports:** this directory (`review/*_review.md`)

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

## Overview

Each flaw-example specification was reviewed with the SKILL.md pipeline (spec goals → threat model → handshake/state → primitives → §3 attack-pattern catalog → §2.10 severity). Reports follow §4 `findings.md` format (mandatory limitations block, findings, coverage matrix, catalog highlights).

## Protocols Reviewed

| Protocol | Source | Report | Verdict | Top issues |
|----------|--------|--------|---------|------------|
| SSL 3.0 | `ssl3_rfc6101.txt` | `ssl3_review.md` | **FAIL** | POODLE/CBC MtE, RSA-PKCS#1 v1.5, export/NULL suites, weak negotiation |
| TLS 1.2 | `tls12_rfc5246.txt` | `tls12_review.md` | **FAIL** | Static RSA/DH, CBC MtE, RC4, renegotiation/resumption binding |
| TLS Compression | `tls1compression.txt` | `tlscompression_review.md` | **FAIL** | Compression before encryption (CRIME/BREACH) |
| IPsec ESP | `ipsec_esp.txt` | `ipsec_esp_review.md` | **FAIL** | Encryption without auth, DES MTI, optional anti-replay |
| IPsec AH | `ipsec_ah.txt` | `ipsec_ah_review.md` | **PASS-WITH-FIXES** | 96-bit ICVs, legacy MACs, optional anti-replay (no conf by design) |
| HMAC-SHA-1-96 | `ipsec_hmac.txt` | `hmac_sha1_96_review.md` | **PASS-WITH-FIXES** | 96-bit tag (C16 Medium), SHA-1 legacy profile |
| ESP NULL | `ipsec_ah_esp.txt` | `ipsec_overview_review.md` | **PASS-WITH-FIXES** | No conf by design; requires strong auth |
| Diffie-Hellman | `dh_key_agreement.txt` | `dh_review.md` | **FAIL** | Optional PK validation, static-static, SHA-1 KDF, weak params |
| EAP KMF | `arpitools.txt` (RFC 5247) | `arp_review.md` | **FAIL** / conditional | Weak methods, channel binding, RADIUS key transport, TSK freshness |

## Catalog Hits (known flaws ↔ pattern IDs)

| Known issue | Protocol(s) | Pattern ID(s) | Caught |
|-------------|-------------|---------------|--------|
| POODLE / CBC MtE | SSL 3.0, TLS 1.2 | C2, C3, I3 | Yes |
| Lucky13 / BEAST class | TLS 1.2 | C2, C3 | Yes |
| CRIME / BREACH | TLS Compression, SSL/TLS optional | C8 | Yes |
| Bleichenbacher / ROBOT | SSL 3.0, TLS 1.2 RSA KE | C15, F1 | Yes |
| RC4 biases | SSL 3.0, TLS 1.2 | C6, N7 | Yes |
| FREAK / Logjam / suite strip | SSL 3.0, TLS 1.2 | N1–N3, R3–R5 | Yes |
| No FS (static RSA/DH) | TLS 1.2, SSL 3.0, DH static-static | F1, F2 | Yes |
| Renegotiation splice | TLS 1.2 (sans RFC 5746) | I7, A5 | Yes |
| Triple Handshake class | TLS 1.2 resumption/export | A3, A5, R8 | Yes |
| ESP conf-only bit-flip | IPsec ESP | C2 | Yes |
| Optional anti-replay | ESP, AH | R9 | Yes |
| 96-bit ICV | AH, HMAC-SHA-1-96, ESP auth | C16 | Yes (Medium, not Critical) |
| Small-subgroup DH | RFC 2631 | K10, PV2, PV4 | Yes |
| EAP channel bind / AAA MSK | RFC 5247 | A5, BIND, K7 | Yes |

## Severity rubric notes (vs older drafts)

- **C16 (96-bit tags):** SKILL.md defaults **Medium** for 64–96-bit tags; online forgery ~2^{tag_bits} (not birthday 2^{48}). AH and HMAC-SHA-1-96 → **PASS-WITH-FIXES**, not FAIL.
- **AH / ESP_NULL confidentiality:** Non-goals when intentional → do not emit Critical “missing encryption.”
- **`arpitools.txt`:** RFC 5247 EAP Key Management Framework — **not** Ethernet ARP.

## Verdict counts

| Verdict | Count |
|---------|-------|
| FAIL | 6 |
| PASS-WITH-FIXES | 3 |
| PASS | 0 |

## Pipeline artifacts

Per-protocol consolidated reports embed Summary, Findings, Coverage Matrix, and Catalog highlights. Intermediate files (`protocol-model.json`, `goals.md`, …) are folded into each `*_review.md` for this validation set rather than stored as separate trees.

## Conclusion

SKILL.md’s §3 catalog and §2.10 rubric identify the historically important design flaws in these specs and assign severities consistent with modern guidance (especially C16 and intentional non-confidentiality modes). Remaining work for human auditors: formal models, implementation side channels, and deployment policy enforcement outside the RFCs.

**Recommendation:** Methodology suitable as a **first-pass protocol design review aid**, not a substitute for expert crypto review or formal verification.
