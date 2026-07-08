# Protocol Review: ARP (Address Resolution Protocol)

**Scope:** protocol logic only
**Source:** RFC 826 (ARP), RFC 5227 (ARP Probe), known protocol flaws

## Summary
Findings: 1 Critical, 2 High, 1 Medium, 0 Low, 1 Info
Verdict: FAIL

## Goals, Threat Model, Invariants, Primitives, Proof Strategy
ARP has no explicit security goals documented. No authentication, no key derivation, no confidentiality.

## Findings

### F-001 — ARP Lacks Mutual Authentication
- **Severity:** Critical
- **Pattern IDs:** A1
- **Location:** ARP protocol design; RFC 826 Section 1.2
- **Description:** ARP has no authentication mechanism whatsoever. Any device on the broadcast domain can send an ARP Reply claiming ownership of any IP-MAC mapping. There is no verification that the sender is authorized to claim the claimed IP address.
- **Attacker scenario:** An attacker connected to the same LAN broadcasts domain can send a forged ARP Reply claiming to own the IP address of the default router. All traffic destined for that IP will be redirected to the attacker (man-in-the-middle).
- **Affected goals:** EA (entity authentication), KA (key agreement - none exists), KCI resistance
- **References:** CVE-1999-0055 / CERT Advisory CA-1996-21; "ARP Cache Poisoning" by Plummer (1982)
- **Fix:** Deploy ARP security extensions such as ARP Security (ARP-SEC) per IEEE 802.1X, use static ARP entries, or deploy network-level protections like switch port security, ARP inspection (DAI), or routing protocols with authentication.

### F-002 — Trust-on-First-Use (TOFU) Without Downgrade Protection
- **Severity:** High
- **Pattern IDs:** A8
- **Location:** ARP cache behavior; RFC 826 Section 2.3.2 (cache entries)
- **Description:** ARP caches entries learned from the first ARP Reply received without any mechanism to detect or prevent subsequent changes. If an attacker sends an ARP Reply first (before the legitimate host), the victim caches the attacker's MAC. There is no downgrade protection or re-authentication of cached entries.
- **Attacker scenario:** An attacker performs an ARP spoofing attack before the legitimate host comes online. The victim caches the attacker's MAC for the target IP. Even when the legitimate host sends a GARP or ARP Reply, the victim ignores it because ARP caches do not update existing entries unless they have expired.
- **Affected goals:** FS (forward secrecy - N/A), KCI, UKS
- **References:** "ARP Poisoning" attack class; ISO/IEC 7498-2
- **Fix:** Implement ARP inspection mechanisms, use persistent static ARP entries, or employ cryptographic ARP protection (e.g., IEEE 802.1X ARPAD authentication).

### F-003 — No Cryptographic Binding Between IP and MAC Addresses
- **Severity:** High
- **Pattern IDs:** A2, BIND (binding goal)
- **Location:** ARP packet structure; RFC 826
- **Description:** ARP does not cryptographically bind the IP address to the MAC address. The IP-MAC mapping is transmitted in plaintext with no authentication, integrity protection, or binding to any trusted third party. There is no mechanism for a central authority to issue authenticated IP-MAC mappings.
- **Attacker scenario:** An attacker intercepts an ARP Reply and modifies the IP-MAC pair. Any device receiving the modified ARP Reply will update its cache with the attacker's MAC address for the victim's IP.
- **Affected goals:** BIND (IP-to-MAC binding), EA, KA
- **References:** RFC 826 (no security provisions); RFC 4941 (Privacy Extensions for SLAAC) does not address ARP
- **Fix:** Use NDP (IPv6 Neighbor Discovery Protocol) with SEND (SEcure Neighbor Discovery) which provides cryptographic verification of address ownership, or employ 802.1X port-based network access control with MAC authentication.

### F-004 — ARP Traffic is Unauthenticated and Unencrypted
- **Severity:** Medium
- **Pattern IDs:** C2, C8
- **Location:** All ARP messages (Request, Reply, GARP, RARP)
- **Description:** ARP packets contain no authentication field and no integrity protection. ARP traffic is sent in plaintext and can be captured, modified, and replayed by any party on the broadcast domain.
- **Attacker scenario:** An attacker passively monitors ARP traffic to map the network topology (which IPs are active and their MAC addresses), then launches targeted spoofing attacks.
- **Affected goals:** CONF (confidentiality - none), INT (integrity - none), EA
- **References:** IEEE 802.3 (Ethernet frame format); RFC 826
- **Fix:** Deploy network segmentation, switch-level ACLs, or move to environments where link-layer encryption (e.g., 802.1AE MACsec) is available.

### F-005 — Lack of Anti-Replay Protection
- **Severity:** Info
- **Pattern IDs:** R1, R9
- **Location:** ARP state machine; RFC 826 Section 2.4
- **Description:** ARP does not include sequence numbers, timestamps, or nonces that would enable detection of replayed ARP messages. Stale ARP Replies can be replayed indefinitely unless the cache entry expires.
- **Attacker scenario:** An attacker records valid ARP Replies and replays them later after the legitimate host has left the network, re-establishing a spoofing position.
- **Affected goals:** REPLAY resistance
- **References:** RFC 5227 (ARP Probe/Announcement) does not add replay protection
- **Fix:** Implement ARP cache timeout enforcement, use dynamic ARP inspection with timestamp validation, or employ cryptographic ARP protections.

## Coverage Matrix
| Goal | Enforced | Confidence | Threat model | Notes |
|------|----------|------------|--------------|-------|
| EA (Entity Authentication) | No | None | N/A | ARP has no authentication |
| KA (Key Agreement) | No | None | N/A | No keys in ARP |
| KS (Key Secrecy) | No | None | N/A | No keys in ARP |
| FS (Forward Secrecy) | N/A | N/A | N/A | No session keys |
| BIND (IP-MAC Binding) | No | None | MITM capable | No cryptographic binding |
| REPLAY | No | None | Replay possible | No sequence numbers |
| IND (Indistinguishability) | No | None | Passive observer sees all | Unencrypted |

## Appendix: ARP Protocol Mechanism

**Purpose:** ARP maps IP addresses to MAC addresses on a local network.

**Messages:**
- ARP Request: broadcast query "Who has IP X? Tell IP Y"
- ARP Reply: unicast response "IP X is at MAC Z"
- GARP (Gratuitous ARP): broadcast announcement "IP X is at MAC Z"
- RARP (Reverse ARP): MAC-to-IP lookup (obsolete)

**Operation:**
1. Host A wants to send to IP B but only knows B's IP
2. A broadcasts ARP Request for IP B
3. Host B (if legitimate) responds with ARP Reply containing its MAC
4. A caches IP-to-MAC mapping in ARP cache
5. Traffic to IP B goes to cached MAC

**Cache Behavior:**
- Entries timeout (typically 20 min default)
- Some implementations never update cached entries until expiry
- No verification of ARP Replies against prior cache state

