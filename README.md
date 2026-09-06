# dhcpv6

A minimal, no-panic **DHCPv6 (RFC 8415) message + option codec** — encode and
parse the client/server message form and its option TLVs — with **zero
dependencies** and zero I/O.

It is a **codec only**: no sockets, no agent, no spoofing logic. Turning
these structures into a service (client, server, or otherwise) is the
consumer's job.

## Guarantees

- **No panics on hostile input.** Option lengths are bounds-checked; malformed
  input returns `Err`.
- **No dependencies.** Pure `std`.

## Example

```rust
use dhcpv6::{Message, DhcpOption, msg_type, opt};
use std::net::Ipv6Addr;

let msg = Message::new(
    msg_type::REPLY,
    [0xAA, 0xBB, 0xCC],
    vec![DhcpOption::dns_servers(&["2001:db8::53".parse::<Ipv6Addr>().unwrap()])],
);
let wire = msg.encode();
let parsed = Message::parse(&wire).unwrap();
assert_eq!(parsed.options[0].code, opt::DNS_SERVERS);
```

## Validation

- **Property-fuzzed**: 100k random + mutated inputs, zero panics
  (`tests/fuzz.rs`).
- **Reference-implementation interop** — verified against `scapy`
  (an independent DHCPv6 stack) in both directions: `scapy`-generated
  REPLY messages round-trip through `dhcpv6::Message::parse` to the exact
  fields (message type, transaction id, options), and `dhcpv6`-built SOLICIT
  messages round-trip through `scapy` to the exact DUID and transaction id.

## Status

`0.x` — unstable API. Client/server message form + generic options today;
relay-forward/relay-reply header variants and typed IA_NA sub-options are out
of scope for now.

## License

MIT.
