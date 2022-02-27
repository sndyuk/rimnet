use anyhow::*;
use clap::Parser;
use lib::gateway::{self, packet::Protocol};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

#[derive(Parser, Debug)]
struct Opts {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    #[clap(version = "1.0")]
    Knock(KnockOpts),
}

#[derive(Parser, Debug)]
struct KnockOpts {
    #[clap(short, long)]
    public_key: String,
    #[clap(long)]
    private_ipv4: String,
    #[clap(long, default_value = "0.0.0.0")]
    public_ipv4: String,
    #[clap(long)]
    external_public_ipv4: String,
    #[clap(long, default_value = "7891")]
    external_public_port: u16,
    #[clap(long)]
    target_external_public_ipv4: String,
    #[clap(short, long, default_value = "7891")]
    target_external_public_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts: Opts = Opts::parse();
    match opts.command {
        Command::Knock(args) => {
            knock(
                &args.private_ipv4,
                &args.public_ipv4,
                &args.external_public_ipv4,
                args.external_public_port,
                base64::decode(args.public_key)?,
                &args.target_external_public_ipv4,
                args.target_external_public_port,
            )
            .await?;
        }
    }

    println!("all done.");
    Ok(())
}

async fn knock(
    private_ipv4: &str,
    public_ipv4: &str,
    external_public_ipv4: &str,
    external_public_port: u16,
    public_key: Vec<u8>,
    target_external_public_ipv4: &str,
    target_external_public_port: u16,
) -> Result<()> {
    // Connect to the remote client
    let mut sock = UdpSocket::bind(format!("{}:0", public_ipv4)).await?;
    println!("binded to the local address {}", sock.local_addr()?);
    let target_addr = format!(
        "{}:{}",
        target_external_public_ipv4, target_external_public_port
    )
    .parse::<SocketAddr>()?;
    println!("connecting to {} ...", target_addr);

    // Knock knock
    let knock_packet = gateway::packet::KnockPacketBuilder::new()?
        .private_ipv4(private_ipv4.parse::<Ipv4Addr>()?)?
        .public_ipv4(external_public_ipv4.parse::<Ipv4Addr>()?)?
        .public_port(external_public_port)?
        .public_key(public_key)?
        .build()?;
    println!("knock packet: {:?}", knock_packet);

    let packet = gateway::packet::PacketBuilder::new()?
        .protocol(Protocol::Knock)?
        .add_payload(knock_packet.as_ref())?
        .build()?;

    println!("packet: {:?}", packet);

    gateway::send(&mut sock, &packet, &target_addr).await?;

    // TODO: Verify the peer accepted the request.
    Ok(())
}
