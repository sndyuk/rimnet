extern crate base64;

use std::net::Ipv4Addr;

use anyhow::Result;
use clap::Parser;
use snow::Builder;
use tracing as log;
use tracing_subscriber;

mod gateway;
mod inbound;
mod private_net;

use private_net::*;

#[derive(Parser)]
#[clap()]
struct Opts {
    #[clap(short = 'n', long)]
    tun_device_name: String,
    #[clap(long, default_value = "10.0.254.1")]
    public_ipv4: String,
    #[clap(short, long, default_value = "7891")]
    public_port: u16,
    #[clap(long)]
    private_ipv4: String,
    #[clap(short, long, default_value = "1500")]
    mtu: i32,
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

    // Prepare keypair for Noise
    let keypair = Builder::new(NOISE_PARAMS.clone()).generate_keypair()?;
    log::info!("public key: {:?}", base64::encode(&keypair.public));

    // Start the inbound network
    inbound::run(inbound::InboundConfig {
        name: opts.tun_device_name,
        mtu: opts.mtu,
        private_ipv4: opts.private_ipv4.parse::<Ipv4Addr>()?,
        public_ipv4: opts.public_ipv4.parse::<Ipv4Addr>()?,
        public_port: opts.public_port,
        keypair,
    })
    .await?;
    Ok(())
}
