use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::{ethernet::EthernetPacket, ip::IpNextHeaderProtocols, Packet};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use inquire::{Text, Select};
use colored::*;
use indicatif::ProgressBar;

fn main() {
    interactive_cli();
}

fn interactive_cli() {
    // Ask the user for the network interface
    let interfaces = datalink::interfaces();
    let interface_names: Vec<String> = interfaces.iter().map(|iface| iface.name.clone()).collect();
    
    let selected_interface = Select::new("Select Network Interface:", interface_names)
        .prompt()
        .expect("Failed to select network interface");

    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == selected_interface)
        .expect("Error: Interface not found");

    // Ask the user for the protocol to filter by
    let protocol = Select::new("Select Protocol to Capture:", vec!["TCP", "UDP", "ICMP", "ALL"])
        .prompt()
        .expect("Failed to select protocol");

    // Ask the user for the port to filter by (optional)
    let port = Text::new("Enter a port to filter by (leave empty for all):")
        .prompt()
        .unwrap();

    // Start capturing packets based on user choices
    start_packet_capture(&interface, &protocol, &port);
}

fn start_packet_capture(interface: &datalink::NetworkInterface, protocol: &str, port: &str) {
    // Create a channel to capture packets
    let (_, mut rx) = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Error: Unknown channel type."),
        Err(e) => panic!("Error: Unable to create datalink channel: {:?}", e),
    };

    println!("Listening on interface: {}", interface.name);

    // Create a progress bar for the packet capture
    let pb = ProgressBar::new(100);

    // Errors below
    pb.set_style(indicatif::ProgressStyle::default_bar().template("{spinner:.green} {msg}").unwrap().progress_chars("##"));

    loop {
        match rx.next() {
            Ok(packet) => {
                // Parse the packet as an Ethernet frame
                let ethernet = EthernetPacket::new(packet).unwrap();
                handle_packet(&ethernet, protocol, port);
            }
            Err(e) => {
                eprintln!("Error: Unable to receive packet: {}", e);
            }
        }

        pb.inc(1); // Increment the progress bar with each packet received
    }
}

fn handle_packet(ethernet: &EthernetPacket, protocol: &str, port: &str) {
    match ethernet.get_ethertype() {
        pnet::packet::ethernet::EtherTypes::Ipv4 => {
            if let Some(ip_packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet.payload()) {
                // Filter by IP protocol
                match ip_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if protocol == "TCP" || protocol == "ALL" {
                            if let Some(tcp) = TcpPacket::new(ip_packet.payload()) {
                                // Filter by port if specified
                                if should_log_packet(port, tcp.get_source(), tcp.get_destination()) {
                                    println!(
                                        "{} TCP: {}:{} -> {}:{}",
                                        "TCP".green(),
                                        ip_packet.get_source(),
                                        tcp.get_source(),
                                        ip_packet.get_destination(),
                                        tcp.get_destination()
                                    );
                                }
                            }
                        }
                    }
                    IpNextHeaderProtocols::Udp => {
                        if protocol == "UDP" || protocol == "ALL" {
                            if let Some(udp) = UdpPacket::new(ip_packet.payload()) {
                                if should_log_packet(port, udp.get_source(), udp.get_destination()) {
                                    println!(
                                        "{} UDP: {}:{} -> {}:{}",
                                        "UDP".blue(),
                                        ip_packet.get_source(),
                                        udp.get_source(),
                                        ip_packet.get_destination(),
                                        udp.get_destination()
                                    );
                                }
                            }
                        }
                    }
                    IpNextHeaderProtocols::Icmp => {
                        if protocol == "ICMP" || protocol == "ALL" {
                            println!(
                                "{} ICMP: {} -> {}",
                                "ICMP".yellow(),
                                ip_packet.get_source(),
                                ip_packet.get_destination()
                            );
                        }
                    }
                    _ => println!("Other IPv4 Packet"),
                }
            }
        }
        _ => println!("Non-IPv4 Packet"),
    }
}

fn should_log_packet(port: &str, source: u16, destination: u16) -> bool {
    port.is_empty() || source == port.parse::<u16>().unwrap() || destination == port.parse::<u16>().unwrap()
}
