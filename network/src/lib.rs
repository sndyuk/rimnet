pub mod config;
pub use config::*;
pub use lib::identity;

mod device;
mod egress;
mod ingress;
mod state;

use anyhow::Result;
use std::sync::Arc;
use tokio::io::ReadHalf;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex};
use tokio_util::codec::FramedRead;
use tracing as log;
use tun::{AsyncDevice, TunPacketCodec};

pub async fn run(config: NetworkConfig) -> Result<()> {
    run_network(config).await
}

async fn run_network(config: NetworkConfig) -> Result<()> {
    let mut device =
        device::NetworkDevice::<FramedRead<ReadHalf<AsyncDevice>, TunPacketCodec>>::create(
            &config.name,
            &config.private_ipv4,
            config.mtu,
        )?;

    // Listen the tunnel(encrypted payload <==> raw payload) traffic port
    let tunnel_sock_addr =
        Arc::new(UdpSocket::bind(format!("{}:{}", config.public_ipv4, config.public_port)).await?);
    // Set 128 to make connections stable.
    tunnel_sock_addr.set_ttl(128)?;
    log::info!(
        "The tunnel listening on {:?}",
        tunnel_sock_addr.local_addr()?
    );

    // Prepare the network
    let network = Arc::new(Mutex::new(state::Network::new(format!(
        "/tmp/rimnet.network-{}",
        config.private_ipv4
    ))?));

    // Inbound incomming loop
    let (tx1, rx1) = oneshot::channel();
    tokio::spawn({
        let tunnel_sock_addr = tunnel_sock_addr.clone();
        let config = config.clone();
        let network = network.clone();
        async move {
            match ingress::listen(&mut device.writer, &tunnel_sock_addr, network, &config).await {
                Ok(_) => tx1.send(true),
                Err(e) => {
                    log::error!(
                        "[Inbound / incomming] Could not recover the error. reason={}",
                        e
                    );
                    tx1.send(false)
                }
            }
        }
    });

    // Inbound outging loop
    let (tx2, rx2) = oneshot::channel();
    tokio::spawn({
        let tunnel_sock_addr = tunnel_sock_addr.clone();
        let config = config.clone();
        let network = network.clone();
        async move {
            match egress::listen(&mut device.reader, &tunnel_sock_addr, network, &config).await {
                Ok(_) => tx2.send(true),
                Err(e) => {
                    log::error!(
                        "[Inbound / outgoing] Could not recover the error. reason={}",
                        e
                    );
                    tx2.send(false)
                }
            }
        }
    });

    tokio::select!(
        _ = rx1 => {
            log::error!("[Inbound / incomming] Killed by unknown error");
        },
        _ = rx2 => {
            log::error!("[Inbound / outgoing] Killed by unknown error");
        }
    );
    Ok(())
}
