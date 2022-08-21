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
    Knock(KnockOpts),
    #[clap(version = "1.0")]
    Cert(CertOpts),
}

#[derive(Parser, Debug)]
struct KnockOpts {
    #[clap(long, default_value = "0.0.0.0")]
    ipv4: String,
    #[clap(short, long, default_value = "7891")]
    port: u16,
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
        Command::Knock(args) => {
            knock(
                &args.ipv4,
                args.port,
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

async fn knock(
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

    // Knock knock
    let knock1_packet = gateway::packet::Knock1PacketBuilder::new()?
        .private_ipv4(target_private_ipv4.parse::<Ipv4Addr>()?)?
        .public_ipv4(target_external_public_ipv4.parse::<Ipv4Addr>()?)?
        .public_port(target_external_public_port)?
        .build()?;

    let packet = gateway::packet::PacketBuilder::new()?
        .protocol(Protocol::Knock1)?
        .add_payload(knock1_packet.as_ref())?
        .build()?;

    gateway::send(&mut sock, &packet, &my_addr).await?;
    println!("Sent knock1 packet: {:?} to {}", knock1_packet, my_addr);
    Ok(())
}

async fn cert(name: &str) -> Result<()> {
    use network::generate_keypair;
    generate_keypair()?.save_to_file(name)?;
    Ok(())
}
