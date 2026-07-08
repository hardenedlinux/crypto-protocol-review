# Flawed Protocol Examples

This directory contains real-world protocol specifications with known security flaws, useful for validating protocol review methodologies.

## Protocols

| File | Protocol | Vulnerability |
|------|----------|---------------|
| `ssl3_rfc6101.txt` | **SSL 3.0** (RFC 6101) | POODLE attack - CBC oracle vulnerability allowing plaintext recovery |
| `tls12_rfc5246.txt` | **TLS 1.2** (RFC 5246) | BEAST, Lucky13, RC4 biases - various cipher-suite weaknesses |
| `tls1compression.txt` | **TLS Compression** (RFC 3749) | CRIME/BREACH - compression side-channel attacks |
| `ipsec_esp.txt` | **IPsec ESP** (RFC 2406) | Encryption without authentication - bit-flipping attacks possible |
| `ipsec_ah.txt` | **IPsec AH** (RFC 2402) | HMAC-MD5 truncation weakness - 96-bit truncation is too short |
| `ipsec_hmac.txt` | **HMAC-SHA-1-96** (RFC 2404) | 96-bit truncation meets minimum but is suboptimal |
| `ipsec_ah_esp.txt` | **IPsec AH/ESP Overview** (RFC 2410) | Lack of implicit IV - IV reuse issues |
| `dh_key_agreement.txt` | **Diffie-Hellman** (RFC 2631) | Small subgroup attack - insufficient public key validation |
| `arpitools.txt` | **ARP** | ARP spoofing - no authentication of ARP replies |

## Vulnerability Summary

- **CBC Oracle**: SSL 3.0, early TLS versions vulnerable to padding oracle attacks
- **Compression Side-Channel**: TLS compression allows traffic injection
- **Weak MAC Truncation**: 96-bit HMAC truncation provides reduced security margin
- **Unauthenticated Encryption**: ESP can be bit-flipped without detection
- **DH Validation**: Missing public key validation enables small subgroup attacks
- **No ARP Authentication**: ARP lacks cryptographic authentication, enabling spoofing

## Usage

These documents are intended for use with `SKILL.md` protocol review methodology validation.
