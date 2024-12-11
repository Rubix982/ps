use crate::utils;

use colored::Colorize;
use pnet::packet::{Packet, tcp::TcpPacket, udp::UdpPacket, ethernet::EthernetPacket, ip::IpNextHeaderProtocols};

pub(crate) fn icmp_handler(ip_packet: pnet::packet::ipv4::Ipv4Packet, protocol: &str) {
    if !matches!(ip_packet.get_next_level_protocol(), IpNextHeaderProtocols::Icmp) {
        log::warn!("Protocol {} is not ICMP", protocol);
        return;
    }

    println!(
        "{} ICMP: {} -> {}",
        "ICMP".yellow(),
        ip_packet.get_source(),
        ip_packet.get_destination()
    );
}

pub(crate) fn udp_handler(ip_packet: pnet::packet::ipv4::Ipv4Packet, protocol: &str, port: &str) {
    if !matches!(protocol, "UDP" | "ALL") {
        log::warn!("Protocol {} is not UDP", protocol);
        return;
    }

    if let Some(udp) = UdpPacket::new(ip_packet.payload()) {
        if utils::should_log_packet(port, udp.get_source(), udp.get_destination()) {
            println!(
                "{} UDP: {}:{} -> {}:{}",
                "UDP".blue(),
                ip_packet.get_source(),
                udp.get_source(),
                ip_packet.get_destination(),
                udp.get_destination()
            );
        }
    } else {
        log::error!("Failed to parse UDP packet");
    }
}

pub(crate) fn tcp_handler(ip_packet: pnet::packet::ipv4::Ipv4Packet, protocol: &str, port: &str) {
    if !matches!(protocol, "TCP" | "ALL") {
        log::warn!("Protocol {} is not TCP", protocol);
        return;
    }

    if let Some(tcp) = TcpPacket::new(ip_packet.payload()) {
        if utils::should_log_packet(port, tcp.get_source(), tcp.get_destination()) {
            println!(
                "{} TCP: {}:{} -> {}:{}",
                "TCP".green(),
                ip_packet.get_source(),
                tcp.get_source(),
                ip_packet.get_destination(),
                tcp.get_destination()
            );
        }
    } else {
        log::error!("Failed to parse TCP packet");
    }
}
