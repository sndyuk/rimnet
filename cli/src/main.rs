use anyhow::*;
use clap::Parser;

#[derive(Parser, Debug)]
struct Opts {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    #[clap(version = "1.0")]
    KnockRequest(KnockRequestOpts),
    #[clap(version = "1.0")]
    Cert(CertOpts),
}

#[derive(Parser, Debug)]
struct KnockRequestOpts {
    #[clap(long, default_value = "0.0.0.0")]
    public_ipv4: String,
    #[clap(short, long, default_value = "7891")]
    public_port: u16,
    #[clap(long)]
    target_private_ipv4: String,
    #[clap(long)]
    target_public_ipv4: String,
    #[clap(short, long, default_value = "7891")]
    target_public_port: u16,
}

#[derive(Parser, Debug)]
struct CertOpts {
    #[clap(short, long)]
    name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts: Opts = Opts::parse();
    match opts.command {
        Command::KnockRequest(args) => {
            knock_request(
                &args.public_ipv4,
                args.public_port,
                &args.target_private_ipv4,
                &args.target_public_ipv4,
                args.target_public_port,
            )
            .await?;
        }
        Command::Cert(args) => {
            cert(&args.name).await?;
        }
    }
    Ok(())
}

async fn knock_request(
    ipv4: &str,
    port: u16,
    target_private_ipv4: &str,
    target_external_public_ipv4: &str,
    target_external_public_port: u16,
) -> Result<()> {
    use lib::gateway::{self, packet::Protocol};
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::net::UdpSocket;

    let my_addr = format!("{}:{}", ipv4, port).parse::<SocketAddr>()?;

    // Connect to the remote client
    let mut sock = UdpSocket::bind(format!("{}:0", ipv4)).await?;
    println!("connecting to {} ...", my_addr);

    // Send the knock request
    let knock_request_packet = gateway::packet::KnockRequestPacketBuilder::new()?
        .private_ipv4(target_private_ipv4.parse::<Ipv4Addr>()?)?
        .public_ipv4(target_external_public_ipv4.parse::<Ipv4Addr>()?)?
        .public_port(target_external_public_port)?
        .build()?;

    let packet = gateway::packet::PacketBuilder::new()?
        .protocol(Protocol::KnockRequest)?
        .source("0.0.0.0".parse::<Ipv4Addr>()?)?
        .add_payload(knock_request_packet.as_ref())?
        .build()?;

    gateway::send(&mut sock, &packet, &my_addr).await?;
    println!(
        "Sent knock packet: {:?} to {}",
        knock_request_packet, my_addr
    );
    Ok(())
}

async fn cert(name: &str) -> Result<()> {
    use network::identity;
    identity::generate_keypair()?.save_to_file(name)?;
    Ok(())
}
