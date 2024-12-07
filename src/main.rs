use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::{ethernet::EthernetPacket, ip::IpNextHeaderProtocols, Packet};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::env;
use clap::{Arg};
use inquire::{Text, Select};
use colored::*;
use indicatif::ProgressBar;

fn main() {
    interactive_cli();
    return;
    // List available network interfaces
    let interfaces = datalink::interfaces();

    println!("Available Network Interfaces:");
    for interface in &interfaces {
        println!("{}", interface);
    }

    // Select an interface (.e.g, eth0)
    let interface_name = env::args().nth(1).expect("Usage: packet_sniffer <INTERFACE>");
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Error: Interface not found");

    // Create a channel to capture packets
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Error: Unknown channel type."),
        Err(e) => panic!("Error: Unable to create datalink channel: {:?}", e),
    };

    println!("Listening on interface: {}", interface.name);

    loop {
        // Receive a packet
        match rx.next() {
            Ok(packet) => {
                // Parse the packet as an Ethernet frame
                let ethernet = EthernetPacket::new(packet).unwrap();
                handle_packet(&ethernet);
            }
            Err(e) => {
                eprintln!("Error: Unable to receive packet: {}", e);
            }
        }
    }
}

// Handle an Ethernet packet
fn handle_packet(ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        // Parse IPv4 packets
        pnet::packet::ethernet::EtherTypes::Ipv4 => {
            if let Some(ip_packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet.payload()) {
                println!(
                    "IPv4 Packet: {} -> {}",
                    ip_packet.get_source(),
                    ip_packet.get_destination()
                );

                match ip_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp) = TcpPacket::new(ip_packet.payload()) {
                            println!(
                                "TCP Packet: {}:{} -> {}:{}",
                                ip_packet.get_source(),
                                tcp.get_source(),
                                ip_packet.get_destination(),
                                tcp.get_destination()
                            );
                        }
                    }
                    IpNextHeaderProtocols::Udp => {
                        if let Some(udp) = UdpPacket::new(ip_packet.payload()) {
                            println!(
                                "UDP Packet: {}:{} -> {}:{}",
                                ip_packet.get_source(),
                                udp.get_source(),
                                ip_packet.get_destination(),
                                udp.get_destination()
                            );
                        }
                    }
                    _ => println!("Other IPv4 Packet"),
                }
            }
        }
        // Parse other protocols if needed
        _ => println!("Non-IPv4 Packet"),
    }
}

fn interactive_cli() {
    let matches = clap::Command::new("Interactive CLI")
        .version("1.0")
        .about("Packet Monitor Tool")
        .arg(
            Arg::new("interactive")
                .short('i')
                .long("interactive")
                .help("Run in interactive mode"),
        )
        .get_matches();

    if matches.contains_id("interactive") {
        println!("{}", "Interactive Mode".cyan().bold());
        let protocol = Select::new(
            "Select a protocol:",
            vec!["TCP", "UDP", "ICMP"],
        )
            .prompt()
            .unwrap();

        let port = Text::new("Enter the port number:")
            .prompt()
            .unwrap();

        println!(
            "{} {} traffic on port {}",
            "Monitoring".green().bold(),
            protocol,
            port
        );

        let bar = ProgressBar::new(100);
        let mut counter = 0;
        while counter < 100 {
            bar.inc(1);
            std::thread::sleep(std::time::Duration::from_millis(20));
            counter += 1;
        }
        bar.finish_with_message("Done!");
    } else {
        println!("{}", "Non-interactive Mode. Use `--interactive` for UI.".red());
    }
}
