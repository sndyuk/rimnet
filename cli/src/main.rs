use anyhow::*;
use clap::Parser;
use lib::gateway::{self, packet::Protocol};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

#[derive(Parser)]
#[clap()]
struct Opts {
    #[clap(short, long)]
    public_key: String,
    #[clap(long)]
    private_ipv4: String,
    #[clap(long)]
    public_ipv4: String,
    #[clap(long, default_value = "7891")]
    public_port: u16,
    #[clap(long)]
    target_public_ipv4: String,
    #[clap(short, long, default_value = "7891")]
    target_public_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts: Opts = Opts::parse();
    knock(
        &opts.private_ipv4,
        &opts.public_ipv4,
        opts.public_port,
        base64::decode(opts.public_key)?,
        &opts.target_public_ipv4,
        opts.target_public_port,
    )
    .await?;
    println!("all done.");
    Ok(())
}

async fn knock(
    private_ipv4: &str,
    public_ipv4: &str,
    public_port: u16,
    local_public_key: Vec<u8>,
    remote_public_ipv4: &str,
    remote_public_port: u16,
) -> Result<()> {
    // Connect to the remote client
    let mut sock = UdpSocket::bind(format!("{}:0", public_ipv4)).await?;
    println!("binded to the local address {}", sock.local_addr()?);
    let server_addr =
        format!("{}:{}", remote_public_ipv4, remote_public_port).parse::<SocketAddr>()?;
    println!("connecting to {} ...", server_addr);

    // Knock knock
    let knock_packet = gateway::packet::KnockPacketBuilder::new()?
        .private_ipv4(private_ipv4.parse::<Ipv4Addr>()?)?
        .public_ipv4(public_ipv4.parse::<Ipv4Addr>()?)?
        .public_port(public_port)?
        .public_key(local_public_key)?
        .build()?;
    println!("knock packet: {:?}", knock_packet);

    let packet = gateway::packet::PacketBuilder::new()?
        .protocol(Protocol::Knock)?
        .add_payload(knock_packet.as_ref())?
        .build()?;

    println!("packet: {:?}", packet);

    gateway::send(&mut sock, &packet, &server_addr).await?;
    Ok(())
}
