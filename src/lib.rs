//! `dhcpv6` — a minimal, no-panic DHCPv6 (RFC 8415) message + option codec.
//!
//! Encode and parse the client/server message form (`msg-type`,
//! 3-byte `transaction-id`, then a list of options) and the option TLVs
//! themselves — with **zero dependencies** and zero I/O.
//!
//! This is a **codec only**: it does not open sockets, and it contains no
//! agent / spoofing logic. Building a rogue advertiser is the consumer's
//! job; this crate just turns bytes into structures and back.
//!
//! ## Parser safety
//!
//! [`Message::parse`] treats input as attacker-controlled: option lengths are
//! bounds-checked against the buffer, and malformed input returns `Err`,
//! never a panic.
//!
//! ```
//! use dhcpv6::{Message, msg_type};
//! let m = Message::parse(&[msg_type::SOLICIT, 0xAA, 0xBB, 0xCC]).unwrap();
//! assert_eq!(m.msg_type, msg_type::SOLICIT);
//! assert_eq!(m.transaction_id, [0xAA, 0xBB, 0xCC]);
//! ```
#![deny(missing_docs)]

use std::net::Ipv6Addr;

/// DHCPv6 message types (RFC 8415 §7.3).
pub mod msg_type {
    /// Client → server: request configuration parameters.
    pub const SOLICIT: u8 = 1;
    /// Server → client: response to SOLICIT.
    pub const ADVERTISE: u8 = 2;
    /// Client → server: request assignment of the ADVERTISEd parameters.
    pub const REQUEST: u8 = 3;
    /// Client → server: confirm addresses are still valid on the current link.
    pub const CONFIRM: u8 = 4;
    /// Client → server: extend lifetimes of assigned parameters (T1).
    pub const RENEW: u8 = 5;
    /// Client → any server: extend lifetimes after failing to RENEW (T2).
    pub const REBIND: u8 = 6;
    /// Server → client: reply to REQUEST / RENEW / REBIND / RELEASE / etc.
    pub const REPLY: u8 = 7;
    /// Client → server: release previously assigned addresses.
    pub const RELEASE: u8 = 8;
    /// Client → server: indicate an address is in use / declined.
    pub const DECLINE: u8 = 9;
    /// Client → server: request information without address assignment.
    pub const INFORMATION_REQUEST: u8 = 11;
}

/// Common DHCPv6 option codes (RFC 8415 §21, RFC 3646 for DNS).
pub mod opt {
    /// Client Identifier — DUID identifying the client.
    pub const CLIENTID: u16 = 1;
    /// Server Identifier — DUID identifying the server.
    pub const SERVERID: u16 = 2;
    /// Identity Association for Non-temporary Addresses.
    pub const IA_NA: u16 = 3;
    /// Option Request — options the client wants the server to return.
    pub const ORO: u16 = 6;
    /// Elapsed time since the client started the DHCPv6 transaction.
    pub const ELAPSED_TIME: u16 = 8;
    /// Status code (RFC 8415 §21.13).
    pub const STATUS_CODE: u16 = 13;
    /// DNS Recursive Name Server list (RFC 3646).
    pub const DNS_SERVERS: u16 = 23;
    /// Domain Search List (RFC 3646).
    pub const DOMAIN_LIST: u16 = 24;
}

/// One DHCPv6 option: a 16-bit code and its raw value bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhcpOption {
    /// Option code (see the [`opt`] module for named constants).
    pub code: u16,
    /// Raw option value bytes.
    pub data: Vec<u8>,
}

impl DhcpOption {
    /// Build an option from a code and its raw value bytes.
    pub fn new(code: u16, data: Vec<u8>) -> Self {
        DhcpOption { code, data }
    }

    /// Build a DNS Recursive Name Server option (code 23): a concatenation of
    /// 16-byte IPv6 addresses (RFC 3646).
    pub fn dns_servers(addrs: &[Ipv6Addr]) -> Self {
        let mut data = Vec::with_capacity(addrs.len() * 16);
        for a in addrs {
            data.extend_from_slice(&a.octets());
        }
        DhcpOption::new(opt::DNS_SERVERS, data)
    }

    /// Parse a DNS Recursive Name Server option's value into addresses.
    /// Returns `None` if the length is not a multiple of 16.
    pub fn as_dns_servers(&self) -> Option<Vec<Ipv6Addr>> {
        if self.code != opt::DNS_SERVERS || !self.data.len().is_multiple_of(16) {
            return None;
        }
        let mut out = Vec::new();
        for chunk in self.data.chunks_exact(16) {
            let mut o = [0u8; 16];
            o.copy_from_slice(chunk);
            out.push(Ipv6Addr::from(o));
        }
        Some(out)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.code.to_be_bytes());
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
    }
}

/// A DHCPv6 client/server message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Message type (see the [`msg_type`] module for named constants).
    pub msg_type: u8,
    /// Transaction id (3 bytes).
    pub transaction_id: [u8; 3],
    /// Message options.
    pub options: Vec<DhcpOption>,
}

impl Message {
    /// Build a message with the given header and options.
    pub fn new(msg_type: u8, transaction_id: [u8; 3], options: Vec<DhcpOption>) -> Self {
        Message {
            msg_type,
            transaction_id,
            options,
        }
    }

    /// Serialize to the wire.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.options.len() * 4);
        out.push(self.msg_type);
        out.extend_from_slice(&self.transaction_id);
        for o in &self.options {
            o.encode_into(&mut out);
        }
        out
    }

    /// Parse a client/server message. Never panics.
    pub fn parse(buf: &[u8]) -> Result<Message, &'static str> {
        if buf.len() < 4 {
            return Err("message shorter than the 4-byte header");
        }
        let msg_type = buf[0];
        let transaction_id = [buf[1], buf[2], buf[3]];
        let options = parse_options(&buf[4..])?;
        Ok(Message {
            msg_type,
            transaction_id,
            options,
        })
    }
}

/// Parse a bare option list (no message header). Never panics.
pub fn parse_options(mut buf: &[u8]) -> Result<Vec<DhcpOption>, &'static str> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 4 {
            return Err("option header truncated");
        }
        let code = u16::from_be_bytes([buf[0], buf[1]]);
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let end = 4usize.checked_add(len).ok_or("option length overflow")?;
        if end > buf.len() {
            return Err("option value past buffer");
        }
        out.push(DhcpOption::new(code, buf[4..end].to_vec()));
        buf = &buf[end..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_roundtrips() {
        let m = Message::new(
            msg_type::ADVERTISE,
            [0x01, 0x02, 0x03],
            vec![
                DhcpOption::new(opt::SERVERID, vec![0xDE, 0xAD]),
                DhcpOption::new(opt::ELAPSED_TIME, vec![0x00, 0x00]),
            ],
        );
        let wire = m.encode();
        assert_eq!(wire[0], msg_type::ADVERTISE);
        assert_eq!(Message::parse(&wire).unwrap(), m);
    }

    #[test]
    fn dns_servers_option_roundtrips() {
        let a = "fe80::1".parse::<Ipv6Addr>().unwrap();
        let b = "2001:db8::53".parse::<Ipv6Addr>().unwrap();
        let o = DhcpOption::dns_servers(&[a, b]);
        assert_eq!(o.code, opt::DNS_SERVERS);
        assert_eq!(o.data.len(), 32);
        assert_eq!(o.as_dns_servers().unwrap(), vec![a, b]);
    }

    #[test]
    fn dns_servers_bad_length_is_none() {
        let o = DhcpOption::new(opt::DNS_SERVERS, vec![0u8; 15]); // not a multiple of 16
        assert!(o.as_dns_servers().is_none());
    }

    #[test]
    fn parse_multiple_options() {
        let m = Message::new(
            msg_type::REPLY,
            [0xAA, 0xBB, 0xCC],
            vec![
                DhcpOption::new(opt::CLIENTID, vec![1, 2, 3, 4]),
                DhcpOption::dns_servers(&["2001:db8::1".parse().unwrap()]),
            ],
        );
        let parsed = Message::parse(&m.encode()).unwrap();
        assert_eq!(parsed.options.len(), 2);
        assert_eq!(parsed.options[0].code, opt::CLIENTID);
        assert_eq!(
            parsed.options[1].as_dns_servers().unwrap(),
            vec!["2001:db8::1".parse::<Ipv6Addr>().unwrap()]
        );
    }

    // ---- hostile inputs: must Err, never panic ----

    #[test]
    fn short_message_errs() {
        assert!(Message::parse(&[1, 2]).is_err());
    }

    #[test]
    fn option_length_past_buffer_errs() {
        // msg header + one option claiming 0xFFFF bytes it doesn't have.
        let buf = [msg_type::SOLICIT, 0, 0, 0, 0x00, 0x17, 0xFF, 0xFF, 0x01];
        assert!(Message::parse(&buf).is_err());
    }

    #[test]
    fn truncated_option_header_errs() {
        let buf = [msg_type::SOLICIT, 0, 0, 0, 0x00, 0x17]; // 2 bytes into an option
        assert!(Message::parse(&buf).is_err());
    }
}
