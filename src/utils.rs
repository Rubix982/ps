pub(crate) fn should_log_packet(port: &str, source: u16, destination: u16) -> bool {
    port.is_empty() || source == port.parse::<u16>().unwrap() || destination == port.parse::<u16>().unwrap()
}
