mod logger;
mod logger_test;
mod utils;
mod handlers;

use std::error::Error;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::{ethernet::EthernetPacket, ip::IpNextHeaderProtocols, Packet};
use inquire::{Text, Select};
use colored::*;
use indicatif::ProgressBar;

fn main() {
    let _ = logger::setup_logger();
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
    let protocols = vec!["TCP", "UDP", "ICMP", "ALL"];
    let protocol = Select::new("Select Protocol to Capture:", protocols)
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
                match ip_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => handlers::tcp_handler(ip_packet, protocol, port),
                    IpNextHeaderProtocols::Udp => handlers::udp_handler(ip_packet, protocol, port),
                    IpNextHeaderProtocols::Icmp => handlers::icmp_handler(ip_packet, protocol),
                    _ => println!("Other IPv4 Packet"),
                }
            }
        }
        _ => println!("Non-IPv4 Packet"),
    }
}
