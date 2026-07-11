# Flawed Protocol Examples

This directory contains protocol specifications and legacy profiles used to validate the `SKILL.md` protocol-review methodology.

## Protocols

| File | Protocol | Review focus |
|------|----------|--------------|
| `ssl3_rfc6101.txt` | SSL 3.0 (RFC 6101) | POODLE/CBC MAC-then-encrypt, RSA-PKCS#1 v1.5, weak/export suites |
| `tls12_rfc5246.txt` | TLS 1.2 (RFC 5246) | Static/RSA key exchange, CBC MtE, legacy suites, renegotiation/resumption binding gaps |
| `tls1compression.txt` | TLS Compression (RFC 3749) | CRIME/BREACH-style compression length oracle |
| `ipsec_esp.txt` | IPsec ESP (RFC 2406) | Encryption without authentication, legacy algorithms, optional anti-replay |
| `ipsec_ah.txt` | IPsec AH (RFC 2402) | 96-bit ICVs, legacy MACs, optional anti-replay |
| `ipsec_hmac.txt` | HMAC-SHA-1-96 (RFC 2404) | 96-bit tag truncation and SHA-1 legacy profile |
| `ipsec_ah_esp.txt` | ESP NULL (RFC 2410) | Authentication without confidentiality and strong-authentication dependency |
| `dh_key_agreement.txt` | Diffie-Hellman (RFC 2631) | Optional public-key validation, weak parameters, SHA-1 KDF, static-static mode |
| `arpitools.txt` | EAP Key Management Framework (RFC 5247) | RADIUS MD5 dependency, channel binding, AAA key transport, lower-layer freshness |

## Notes

- `arpitools.txt` is RFC 5247, not ARP.
- HMAC-SHA-1-96's 96-bit tag has an online forgery cost of about 2^96 attempts; it is still below the modern 128-bit tag floor in `SKILL.md`.
- AH and ESP_NULL intentionally do not provide confidentiality; findings only apply when a deployment expects confidentiality or pairs them with weak/NULL authentication.

## Usage

Use these documents with `SKILL.md` for protocol-level review validation. The matching reports are in `review/`.
