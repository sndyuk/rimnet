use anyhow::Result;
use std::net::Ipv4Addr;

use futures::StreamExt;
use lib::gateway;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::ReadHalf;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::codec::FramedRead;
use tracing as log;
use tun::{AsyncDevice, IntoAddress, TunPacketCodec};

use super::config::*;
use super::state::*;
use crate::device;

// Transfer message from the TUN device to the remote peer
pub async fn listen(
    tun_reader: &mut FramedRead<ReadHalf<AsyncDevice>, TunPacketCodec>,
    main_sock: &UdpSocket,
    network: Arc<Mutex<Network>>,
    config: &NetworkConfig,
) -> Result<()> {
    let mut peers_cache: HashMap<Ipv4Addr, Peer> = HashMap::new();

    loop {
        match tun_reader.next().await {
            Some(Ok(raw_packet)) => {
                // Raw packet received from the TUN device
                let raw_packet_bytes = raw_packet.get_bytes();

                // It should be IPv4 packet. Otherwise, drop it.
                let payload_packet = match raw_packet_bytes[0] >> 4 {
                    4 => packet::ip::v4::Packet::unchecked(raw_packet_bytes),
                    6 => {
                        log::trace!("Drop the packet. protocol=IPv6");
                        continue;
                    }
                    _ => {
                        log::warn!(
                            "Drop the packet. protocol=unknown, data={:?}",
                            raw_packet_bytes
                        );
                        continue;
                    }
                };

                let peer_private_ipv4 = payload_packet.destination();
                if raw_packet_bytes.len() == 30 // Includes IP and UDP packet header
                    && raw_packet_bytes[28..30] == device::SYNC_PACKET
                {
                    log::trace!("Sync the peer state of '{}'", peer_private_ipv4);
                    let network = network.lock().await;
                    if let (Some(peer_node), Some(ts)) = network.get(&peer_private_ipv4)? {
                        peers_cache.insert(
                            peer_private_ipv4,
                            Peer {
                                ts,
                                public_addr: peer_node.public_addr,
                                public_addr_hole: peer_node.public_addr_hole,
                            },
                        );
                    }
                    continue;
                }

                if peer_private_ipv4.is_multicast() {
                    // TODO: It should be configurable whether skip or ingest. Need any concrete usecase.
                    log::trace!("Drop the multicast packet. {}", peer_private_ipv4);
                    continue;
                }
                if peer_private_ipv4.is_broadcast() {
                    // TODO: It should be configurable whether skip or ingest. Need any concrete usecase.
                    log::trace!("Drop the broadcast packet. {}", peer_private_ipv4);
                    continue;
                }

                let mut peer = peers_cache.get_mut(&peer_private_ipv4);
                if peer.is_none() {
                    let network = network.lock().await;
                    match network.get(&peer_private_ipv4)? {
                        (Some(peer_node), Some(ts)) => {
                            peers_cache.insert(
                                peer_private_ipv4,
                                Peer {
                                    ts,
                                    public_addr: peer_node.public_addr,
                                    public_addr_hole: peer_node.public_addr_hole,
                                },
                            );
                            peer = peers_cache.get_mut(&peer_private_ipv4);
                        }
                        // Keep waiting for the response from the peer...
                        (Some(peer_node), None) => {
                            log::info!(
                                "Peer not found. Wait for a sec or manually connect to the peer using CLI(knock-request command). peer_privat_ipv4={}",
                                peer_private_ipv4
                            );
                            // When this node is restarted and the peer has been connected before, it will reconnnect again.
                            // In the case the peer's public key or nonce is changed, a user must execute the knock-request CLI command manually.
                            gateway::send(
                                &main_sock,
                                &gateway::packet::PacketBuilder::new()?
                                    .protocol(gateway::packet::Protocol::KnockRequest)?
                                    .source(config.private_ipv4)?
                                    .add_payload(
                                        gateway::packet::KnockRequestPacketBuilder::new()?
                                            .private_ipv4(peer_private_ipv4)?
                                            .public_ipv4(
                                                peer_node.public_addr_hole.ip().into_address()?,
                                            )?
                                            .public_port(peer_node.public_addr_hole.port())?
                                            .build()?
                                            .as_ref(),
                                    )?
                                    .build()?,
                                &main_sock.local_addr()?,
                            )
                            .await?;
                            continue;
                        }
                        // Not found in the private network.
                        // Someone in the network may know the peer's public address. Try to find it.
                        (None, _) => {
                            log::debug!(
                                "Peer not found. Ask the peer to the connected {} neighbor(s). peer_privat_ipv4={}",
                                peer_private_ipv4, peers_cache.len()
                            );
                            // TODO tests
                            // Query the peer's info to other peers and knock to the peer.
                            let query_packet = gateway::packet::QueryPacketBuilder::new()?
                                .public_ipv4(config.public_ipv4)?
                                .public_port(config.public_port)?
                                .target_private_ipv4(peer_private_ipv4)?
                                .public_key(&config.public_key)?
                                .build()?;

                            // Multicast the knock request.
                            for (_, peer) in peers_cache.iter() {
                                let packet = gateway::packet::PacketBuilder::new()?
                                    .protocol(gateway::packet::Protocol::Query)?
                                    .source(config.private_ipv4)?
                                    .add_payload(query_packet.as_ref())?
                                    .build()?;

                                log::trace!("query packet: {:?}", query_packet);
                                gateway::send(&main_sock, &packet, &peer.public_addr_hole).await?;
                            }
                            continue;
                        }
                    }
                }
                log::debug!("Transferring the packet");
                let peer = peer.unwrap();
                let raw_packet = gateway::packet::TcpIpPacketBuilder::new()?
                    .add_payload(payload_packet.as_ref())?
                    .build()?;

                let mut buf = [0u8; 65535];
                let encrypted_packet_len =
                    peer.ts.write_message(0, raw_packet.as_ref(), &mut buf)?;

                // Wrap the encrypted packet
                let packet = gateway::packet::PacketBuilder::new()?
                    .protocol(gateway::packet::Protocol::TcpIp)?
                    .source(config.private_ipv4)?
                    .add_payload(&buf[..encrypted_packet_len])?
                    .build()?;

                match gateway::send(main_sock, &packet, &peer.public_addr_hole).await {
                    Ok(_) => {
                        log::debug!(
                            "Sent packet. peer_private={}, peer_public={}",
                            peer_private_ipv4,
                            peer.public_addr_hole
                        );
                        log::trace!(
                            "payload: {:?} (encrypted={:?})",
                            payload_packet,
                            &buf[..encrypted_packet_len],
                        );
                    }
                    Err(e) => {
                        log::warn!(
                            "Could not send the data. peer_private={}, reason={}",
                            peer_private_ipv4,
                            e
                        );
                    }
                }
            }
            Some(Err(e)) => {
                log::warn!("Could not read the UDP packet. reason={}", e);
                continue;
            }
            None => {
                log::warn!("Could not read the UDP packet. reason=unknown");
                continue;
            }
        }
    }
}
