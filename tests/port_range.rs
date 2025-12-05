use port_scanner::PortRange;

#[test]
fn parse_ports_ok() {
    let r: PortRange = "1-1000".parse().unwrap();
    assert_eq!(r.start, 1);
    assert_eq!(r.end, 1000);
}

#[test]
fn parse_ports_rejects_zero() {
    assert!("0-10".parse::<PortRange>().is_err());
    assert!("1-0".parse::<PortRange>().is_err());
}

#[test]
fn parse_ports_rejects_reverse() {
    assert!("100-1".parse::<PortRange>().is_err());
}
