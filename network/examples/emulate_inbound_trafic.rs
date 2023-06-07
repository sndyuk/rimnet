extern crate base64;
extern crate tun;

use anyhow::*;
use clap::Parser;
use lib::gateway::{self, packet::Protocol};
use packet::{self, Builder as packet_builder, Packet as _};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

#[derive(Parser)]
#[clap()]
struct Opts {
    #[clap(long, default_value = "127.0.0.1")]
    host_ipv4: String,
    #[clap(long, default_value = "10.0.254.1")]
    public_ipv4: String,
    #[clap(short, long, default_value = "7891")]
    public_port: u16,
    #[clap(long, default_value = "10.0.0.4")]
    target_private_ipv4: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts: Opts = Opts::parse();
    send_sample_messages(
        &opts.host_ipv4,
        &opts.public_ipv4,
        opts.public_port,
        &opts.target_private_ipv4,
    )
    .await?;
    println!("all done.");
    Ok(())
}

async fn send_sample_messages(
    host_ipv4: &str,
    public_ipv4: &str,
    public_port: u16,
    target_private_ipv4: &str,
) -> Result<()> {
    // Connect to the remote node
    let mut sock = UdpSocket::bind(format!("{}:0", host_ipv4)).await?;
    println!("binded to the local address {}", sock.local_addr()?);
    let server_addr = format!("{}:{}", public_ipv4, public_port).parse::<SocketAddr>()?;
    println!("connecting to {} ...", server_addr);

    // Send data
    for _ in 0..1 {
        let sample_ipv4_packet = packet::ip::v4::Packet::unchecked(
            packet::ip::v4::Builder::default()
                .protocol(packet::ip::Protocol::Udp)?
                .id(44616)?
                // .flags(packet::ip::v4::Flags::MORE_FRAGMENTS)?
                .ttl(64)?
                .source("10.0.0.99".parse::<Ipv4Addr>()?)?
                .destination(target_private_ipv4.parse::<Ipv4Addr>()?)?
                .udp()?
                .source(8080)?
                .destination(8080)?
                .payload(b"HELLO RIMNET\n")?
                .build()?,
        );
        println!(
            "payload(HEX): {:?}",
            sample_ipv4_packet
                .payload()
                .iter()
                .map(|n| format!("{:02X}", n))
                .collect::<String>()
        );

        let capability: [u8; 8] = [
            0b0000_0010,
            0b0000_0010,
            0b0000_0100,
            0b0000_0100,
            0b0000_1000,
            0b0000_1000,
            0b0000_1111,
            0b0000_0111,
        ];

        let tcpip_packet = gateway::packet::TcpIpPacketBuilder::new()?
            .capability(capability.to_vec())?
            .add_payload(sample_ipv4_packet.as_ref())?
            .build()?;
        println!("tcpip packet: {:?}", tcpip_packet);

        // let tcpip_len = noise.write_message(tcpip_packet.as_ref(), &mut buf)?;
        // println!("encrypted tcpip packet length: {:?}", tcpip_len);

        let packet = gateway::packet::PacketBuilder::new()?
            .protocol(Protocol::TcpIp)?
            .source("0.0.0.0".parse::<Ipv4Addr>()?)?
            .add_payload(tcpip_packet.as_ref())?
            .build()?;
        println!("packet: {:?}", packet);

        gateway::send(&mut sock, &packet, &server_addr).await?;
    }
    Ok(())
}
