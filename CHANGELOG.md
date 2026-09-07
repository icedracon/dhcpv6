# Changelog

All notable changes to `dhcpv6` are documented here. Follows
[Keep a Changelog](https://keepachangelog.com); uses SemVer.

## [0.1.0] � 2026-09-06

First stable release of the RFC 8415 DHCPv6 message + option codec.

### Validated
- 100k random + mutated inputs � `Message::parse` never panics.
- Bidirectional interop with `scapy` (an independent DHCPv6 stack): a
  scapy-generated REPLY parses to the exact fields, and a `dhcpv6`-built
  SOLICIT decodes cleanly through scapy.

### Future (additive)
- Relay-Forward / Relay-Reply support will land as a separate message type
  (additive, non-breaking).

## [0.1.0-beta.1] — unreleased

Initial release. Unstable API (0.x + beta) — expect small breaks before 0.1.0.

### Added
- RFC 8415 client/server message form: `Message::new`, `encode`, `parse`.
- Generic `DhcpOption` TLV encode/decode.
- Convenience helpers for DNS Recursive Name Server (`DhcpOption::dns_servers`
  / `DhcpOption::as_dns_servers`).
- Named constants for the standard message types (SOLICIT/ADVERTISE/…) and
  common option codes (CLIENTID/SERVERID/IA_NA/ORO/DNS_SERVERS/…).
- Zero dependencies (pure `std`).

### Validated
- 9 unit tests + one doctest cover message + option round-trips, hostile
  option lengths, and DNS-servers option shape.
- 100k random + mutated inputs — parser never panics (`tests/fuzz.rs`).
- Reference interop: parsed a `scapy`-generated DHCPv6 REPLY to the exact
  fields (msg type, transaction id, DNS servers), and scapy decoded a
  `dhcpv6`-built SOLICIT to the exact DUID and transaction id.

### Not included (deliberately)
- Relay-Forward / Relay-Reply message headers.
- Typed sub-option decoding (IA_NA / IA_TA / IAADDR).
- Any active agent / listener logic — this is a codec.
