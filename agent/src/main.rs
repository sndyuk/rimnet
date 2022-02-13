extern crate base64;

use std::net::Ipv4Addr;

use anyhow::Result;
use clap::Parser;
use tracing as log;
use tracing_subscriber;

use lib::*;

#[derive(Parser)]
#[clap()]
struct Opts {
    #[clap(short = 'n', long)]
    tun_device_name: Option<String>,
    #[clap(long)]
    private_ipv4: Option<String>,
    #[clap(long)]
    public_ipv4: Option<String>,
    #[clap(short, long)]
    public_port: Option<u16>,
    #[clap(short, long)]
    mtu: Option<i32>,
    #[clap(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts: Opts = Opts::parse();

    // Configure logger
    tracing_subscriber::fmt::Subscriber::builder()
        .with_env_filter(
            tracing_subscriber::filter::EnvFilter::try_from_env("RIMNET_LOG").unwrap_or_else(
                |_| {
                    tracing_subscriber::filter::EnvFilter::new(if opts.verbose {
                        "TRACE"
                    } else {
                        "INFO"
                    })
                },
            ),
        )
        .pretty()
        .init();

    // Prepare keypair of the agent
    let keypair = generate_keypair()?;
    log::info!("public key: {:?}", base64::encode(&keypair.public));

    // Start the inbound network
    let mut network_config_builder =
        NetworkConfigBuilder::new()?.keypair(keypair.private, keypair.public)?;

    if let Some(v) = opts.tun_device_name {
        network_config_builder = network_config_builder.name(v)?;
    };
    if let Some(v) = opts.mtu {
        network_config_builder = network_config_builder.mtu(v)?;
    }
    if let Some(v) = opts.private_ipv4 {
        network_config_builder = network_config_builder.private_ipv4(v.parse::<Ipv4Addr>()?)?;
    }
    if let Some(v) = opts.public_ipv4 {
        network_config_builder = network_config_builder.public_ipv4(v.parse::<Ipv4Addr>()?)?;
    }
    if let Some(v) = opts.public_port {
        network_config_builder = network_config_builder.public_port(v)?;
    }
    network::run(network_config_builder.build()?).await?;
    Ok(())
}