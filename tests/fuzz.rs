//! Deterministic no-panic fuzz for the DHCPv6 message/option parser.
use dhcpv6::{msg_type, opt, parse_options, DhcpOption, Message};
fn xs(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}
#[test]
fn never_panics_on_hostile_input() {
    let mut s: u64 = 0x1357_9BDF_0246_8ACE;
    let seed = Message::new(
        msg_type::REPLY,
        [1, 2, 3],
        vec![
            DhcpOption::new(opt::CLIENTID, vec![1, 2, 3, 4]),
            DhcpOption::dns_servers(&["2001:db8::1".parse().unwrap()]),
        ],
    )
    .encode();
    assert!(Message::parse(&seed).is_ok());
    for _ in 0..100_000 {
        let bytes = if xs(&mut s) & 1 == 0 {
            let n = (xs(&mut s) % 96) as usize;
            (0..n)
                .map(|_| (xs(&mut s) & 0xff) as u8)
                .collect::<Vec<u8>>()
        } else {
            let mut m = seed.clone();
            let i = (xs(&mut s) as usize) % m.len();
            m[i] ^= (xs(&mut s) & 0xff) as u8;
            m
        };
        let _ = Message::parse(&bytes);
        let _ = parse_options(&bytes);
    }
}
