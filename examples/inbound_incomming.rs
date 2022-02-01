extern crate base64;
extern crate tun;

use lazy_static::lazy_static;

use anyhow::{Context, Result};
use clap::Parser;
use packet::{self, tcp::Flags, AsPacket, Builder as packet_builder, Packet as _};
use rimnet::{
    gateway::{self, packet::Protocol},
    network,
};
use snow::{params::NoiseParams, Builder};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

lazy_static! {
    // TODO Be customizable
    pub static ref NOISE_PARAMS: NoiseParams = "Noise_N_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

#[derive(Parser)]
#[clap()]
struct Opts {
    #[clap(short, long)]
    key: String,
    #[clap(long, default_value = "127.0.0.1")]
    host_ipv4: String,
    #[clap(long, default_value = "10.0.254.1")]
    target_public_ipv4: String,
    #[clap(short, long, default_value = "7891")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts: Opts = Opts::parse();
    let remote_public_key = opts.key;
    let host_ipv4 = opts.host_ipv4;
    let target_public_ipv4 = opts.target_public_ipv4;
    let port = opts.port;
    println!("public key: {:?}", remote_public_key);
    send_sample_messages(
        &base64::decode(remote_public_key)?,
        &host_ipv4,
        &target_public_ipv4,
        port,
    )
    .await?;
    println!("all done.");
    Ok(())
}

async fn send_sample_messages(
    remote_public_key: &Vec<u8>,
    host_ipv4: &str,
    target_public_ipv4: &str,
    port: u16,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];

    let builder: Builder<'_> = Builder::new(NOISE_PARAMS.clone());
    let local_keypair = builder.generate_keypair()?;
    let mut noise = builder
        .local_private_key(&local_keypair.private)
        .remote_public_key(remote_public_key)
        .build_initiator()?;

    // Connect to the remote client
    let mut sock = UdpSocket::bind(format!("{}:0", host_ipv4)).await?;
    println!("binded to the local address {}", sock.local_addr()?);
    let server_addr = format!("{}:{}", target_public_ipv4, port).parse::<SocketAddr>()?;
    println!("connecting to {} ...", server_addr);

    // Start handshake
    let handshake_packet = gateway::packet::HandshakePacketBuilder::new()?
        .source_ipv4(Ipv4Addr::new(10, 0, 0, 2))?
        .public_key(local_keypair.public)?
        .build()?;
    println!("handshake packet: {:?}", handshake_packet);

    let handshake_len = noise.write_message(handshake_packet.as_ref(), &mut buf)?;
    println!("encrypted handshake packet length: {:?}", handshake_len);

    let packet = gateway::packet::PacketBuilder::new()?
        .protocol(Protocol::Handshake)?
        .add_payload(&buf[..handshake_len])?
        .build()?;

    println!("packet: {:?}", packet);

    gateway::send(&mut sock, packet.as_ref(), &server_addr).await?;

    let mut noise = noise.into_transport_mode()?;
    println!("session established");

    // Send data
    for _ in 0..1 {
        let ipv4_packet = packet::ip::v4::Packet::unchecked(
            packet::ip::v4::Builder::default()
                .protocol(packet::ip::Protocol::Udp)?
                .id(44616)?
                // .flags(packet::ip::v4::Flags::MORE_FRAGMENTS)?
                .ttl(64)?
                .source(Ipv4Addr::new(10, 0, 0, 2))?
                .destination(Ipv4Addr::new(10, 0, 0, 3))?
                .udp()?
                .source(8080)?
                .destination(8080)?
                .payload(b"HELLO RIMNET\n")?
                .build()?,
        );
        println!(
            "payload(HEX): {:?}",
            ipv4_packet
                .payload()
                .iter()
                .map(|n| format!("{:02X}", n))
                .collect::<String>()
        );

        let cap: [u8; 8] = [
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
            .source_ipv4(Ipv4Addr::new(10, 0, 0, 2))?
            .capability(cap.to_vec())?
            .add_payload(ipv4_packet.as_ref())?
            .build()?;
        println!("tcpip packet: {:?}", tcpip_packet);

        let tcpip_len = noise.write_message(tcpip_packet.as_ref(), &mut buf)?;
        println!("encrypted tcpip packet length: {:?}", tcpip_len);

        let packet = gateway::packet::PacketBuilder::new()?
            .protocol(Protocol::TcpIp)?
            .add_payload(&buf[..tcpip_len])?
            .build()?;
        println!("packet: {:?}", packet);

        gateway::send(&mut sock, packet.as_ref(), &server_addr).await?;
    }
    Ok(())
}
