use anyhow::Result;
use std::net::Ipv4Addr;

use lib::{gateway, identity};
use std::sync::Arc;
use std::{collections::HashMap, net::SocketAddr};
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing as log;
use tun::{AsyncDevice, IntoAddress};

use super::config::*;
use super::state::*;
use crate::device;

use snow::{Builder as HandshakeBuilder, HandshakeState};

// Consume messages comming from the tunnel
pub async fn listen(
    tun_writer: &mut WriteHalf<AsyncDevice>,
    main_sock: &UdpSocket,
    network: Arc<Mutex<Network>>,
    config: &NetworkConfig,
) -> Result<()> {
    // Key: private IPv4 of the peer
    let mut peers_cache: HashMap<Ipv4Addr, Peer> = HashMap::new();
    let mut hs_cache: HashMap<Ipv4Addr, HandshakeState> = HashMap::new();
    loop {
        match gateway::recv(main_sock).await {
            Ok((mut packet, peer_public_addr_hole)) => {
                if !packet.is_valid() {
                    log::warn!("Ignore the invalid packet");
                    continue;
                }
                match packet.protocol() {
                    gateway::packet::Protocol::KnockRequest => {
                        log::debug!("Received a knock request");
                        match packet.to_knock_request() {
                            Ok(knock_request_packet) => {
                                // Reserve the node
                                let reserved_node = network
                                    .lock()
                                    .await
                                    .reserve_node_knock(knock_request_packet.private_ipv4())?;

                                // Send knock packet
                                let knock_packet = gateway::packet::KnockPacketBuilder::new()?
                                    .nonce(reserved_node.nonce)?
                                    .public_ipv4(config.public_ipv4)?
                                    .public_port(config.public_port)?
                                    .public_key(&config.public_key)?
                                    .build()?;

                                log::trace!("knock packet: {:?}", knock_packet);
                                let packet = gateway::packet::PacketBuilder::new()?
                                    .protocol(gateway::packet::Protocol::Knock)?
                                    .source(config.private_ipv4)?
                                    .add_payload(knock_packet.as_ref())?
                                    .build()?;

                                // Note: `peer_public_addr_hole` is the CLI client's address. Not the peer's address.
                                let peer_public_addr = format!(
                                    "{}:{}",
                                    knock_request_packet.public_ipv4(),
                                    knock_request_packet.public_port()
                                )
                                .parse::<SocketAddr>()?;
                                gateway::send(main_sock, &packet, &peer_public_addr).await?;
                                log::debug!("sent knock request. peer_public={}", peer_public_addr);
                            }
                            Err(e) => {
                                log::warn!("Knock request failed. reason={}", e);
                            }
                        }
                    }
                    gateway::packet::Protocol::Knock => {
                        log::debug!("Received a knock");
                        match packet.to_knock() {
                            Ok(knock_packet) => {
                                // Reserve the node
                                network.lock().await.reserve_node_handshake(
                                    packet.source(),
                                    knock_packet.nonce(),
                                )?;
                                // TODO Confirm the peer node after vaidating it with the owner.

                                // Start handshake
                                let handshake_packet =
                                    gateway::packet::HandshakePacketBuilder::new()?
                                        .nonce(knock_packet.nonce())?
                                        .public_ipv4(config.public_ipv4)?
                                        .public_port(config.public_port)?
                                        .public_key(&config.public_key)?
                                        .build()?;

                                log::trace!("handshake packet: {:?}", handshake_packet);
                                let mut hs = HandshakeBuilder::new(identity::NOISE_PARAMS.clone())
                                    .local_private_key(&config.private_key)
                                    .remote_public_key(knock_packet.public_key().as_ref())
                                    .build_initiator()?;

                                let mut buf = [0u8; 127];
                                let handshake_len =
                                    hs.write_message(handshake_packet.as_ref(), &mut buf)?;
                                assert!(handshake_len <= 127);

                                gateway::send(
                                    main_sock,
                                    &gateway::packet::PacketBuilder::new()?
                                        .protocol(gateway::packet::Protocol::Handshake)?
                                        .source(config.private_ipv4)?
                                        .add_payload(&buf[..handshake_len])?
                                        .build()?,
                                    &peer_public_addr_hole,
                                )
                                .await?;

                                hs_cache.insert(packet.source(), hs);
                                log::debug!(
                                    "Sent handshake request. peer_private={}, peer_public={}",
                                    packet.source(),
                                    peer_public_addr_hole
                                );

                                log::info!("Knock accepted: peer_private={}", packet.source(),);
                            }
                            Err(e) => {
                                log::warn!(
                                    "Knock failed. peer_public={}, reason={}",
                                    peer_public_addr_hole,
                                    e
                                );
                            }
                        };
                    }
                    gateway::packet::Protocol::Handshake => {
                        log::debug!("Start handshake");
                        log::trace!("packet: {:?}", packet);

                        let mut hs = HandshakeBuilder::new(identity::NOISE_PARAMS.clone())
                            .local_private_key(&config.private_key)
                            .build_responder()?;
                        match packet.to_handshake(&mut hs) {
                            Ok(handshake_packet) => {
                                let peer_public_addr = format!(
                                    "{}:{}",
                                    handshake_packet.public_ipv4(),
                                    handshake_packet.public_port(),
                                )
                                .parse::<SocketAddr>()?;
                                log::debug!("Handshake received. peer_public={}", peer_public_addr);

                                let handshake_accept_packet =
                                    gateway::packet::HandshakeAcceptPacketBuilder::new()?
                                        .nonce(handshake_packet.nonce())?
                                        .public_ipv4(config.public_ipv4)?
                                        .public_port(config.public_port)?
                                        .public_key(&config.public_key)?
                                        .build()?;

                                log::trace!(
                                    "handshake_accept packet: {:?}",
                                    handshake_accept_packet
                                );
                                let mut buf = [0u8; 127];
                                let handshake_accept_len =
                                    hs.write_message(handshake_accept_packet.as_ref(), &mut buf)?;
                                assert!(handshake_accept_len <= 127);

                                gateway::send(
                                    main_sock,
                                    &gateway::packet::PacketBuilder::new()?
                                        .protocol(gateway::packet::Protocol::HandshakeAccept)?
                                        .source(config.private_ipv4)?
                                        .add_payload(&buf[..handshake_accept_len])?
                                        .build()?,
                                    &peer_public_addr_hole,
                                )
                                .await?;

                                let ts = Arc::new(hs.into_stateless_transport_mode()?);
                                let mut network = network.lock().await;
                                network.confirm_node(
                                    &packet.source(),
                                    handshake_packet.nonce(),
                                    peer_public_addr,
                                    peer_public_addr_hole,
                                    handshake_packet.public_key(),
                                    ts.clone(),
                                )?;

                                let peer = Peer {
                                    ts: ts.clone(),
                                    public_addr: peer_public_addr,
                                    public_addr_hole: peer_public_addr_hole,
                                };
                                if let Some(old_peer) = peers_cache.insert(packet.source(), peer) {
                                    log::debug!(
                                        "Update old peer state. old peer_public={}, new peer_public={}",
                                        old_peer.public_addr_hole, peer_public_addr_hole
                                    );
                                };
                                log::info!(
                                    "Session established: peer_private={}, peer_public={}, peer_public_hole={}",
                                    packet.source(),
                                    peer_public_addr,
                                    peer_public_addr_hole,
                                );
                            }
                            Err(e) => {
                                log::warn!(
                                    "Handshake failed. peer_public={}, reason={}",
                                    peer_public_addr_hole,
                                    e
                                );
                            }
                        }
                    }
                    gateway::packet::Protocol::HandshakeAccept => {
                        log::debug!("Start handshake accept");
                        log::trace!("packet: {:?}", packet);

                        let hs = hs_cache.remove(&packet.source());
                        if hs.is_none() {
                            log::debug!("Invalid packet. Required knock packet first.");
                            continue;
                        }
                        let mut hs = hs.unwrap();
                        match packet.to_handshake_accept(&mut hs) {
                            Ok(handshake_accept_packet) => {
                                let peer_public_addr = format!(
                                    "{}:{}",
                                    handshake_accept_packet.public_ipv4(),
                                    handshake_accept_packet.public_port(),
                                )
                                .parse::<SocketAddr>()?;
                                log::debug!("Handshake accepted. peer_public={}", peer_public_addr);

                                let ts = Arc::new(hs.into_stateless_transport_mode()?);
                                let mut network = network.lock().await;
                                network.confirm_node(
                                    &packet.source(),
                                    handshake_accept_packet.nonce(),
                                    peer_public_addr,
                                    peer_public_addr_hole,
                                    handshake_accept_packet.public_key(),
                                    ts.clone(),
                                )?;

                                let peer = Peer {
                                    ts: ts.clone(),
                                    public_addr: peer_public_addr,
                                    public_addr_hole: peer_public_addr_hole,
                                };
                                if let Some(old_peer) = peers_cache.insert(packet.source(), peer) {
                                    log::debug!(
                                        "Update old peer state. old peer_public={}, new peer_public={}",
                                        old_peer.public_addr_hole, peer_public_addr_hole
                                    );
                                };
                                log::info!(
                                    "Session established: peer_private={}, peer_public={}, peer_public_hole={}",
                                    packet.source(),
                                    peer_public_addr,
                                    peer_public_addr_hole,
                                );

                                // It's just a signal to the outgoing channel to resync the new peer state.
                                gateway::send_raw(
                                    main_sock,
                                    device::SYNC_PACKET,
                                    &format!("{}:255", packet.source()).parse::<SocketAddr>()?,
                                )
                                .await?;
                            }
                            Err(e) => {
                                log::warn!(
                                    "Handshake accept failed. peer_public={}, reason={}",
                                    peer_public_addr_hole,
                                    e
                                );
                            }
                        }
                    }
                    gateway::packet::Protocol::TcpIp => {
                        match peers_cache.get_mut(&packet.source()) {
                            Some(peer) => {
                                match packet.to_tcpip(peer.ts.as_ref()) {
                                    Ok(tcpip_packet) => {
                                        log::trace!(
                                            "Accept the TcpIp packet: {:?}",
                                            tcpip_packet.payload().as_ref()
                                        );
                                        // Afer the handshake
                                        tun_writer
                                            .write_all(
                                                &[
                                                    // Add IPv4 packet information
                                                    #[cfg(target_os = "linux")]
                                                    &[0x00, 0x00, 0x08, 0x00], // libc::ETH_P_IP
                                                    #[cfg(target_os = "macos")]
                                                    &[0x00, 0x00, 0x00, 0x02], // libc::PF_INET
                                                    tcpip_packet.payload().as_ref(),
                                                ]
                                                .concat(),
                                            )
                                            .await?;
                                    }
                                    Err(e) => {
                                        log::warn!(
                                            "Could not extract the payload. Retry handshake manually. peer_public={}. reason={}",
                                            peer_public_addr_hole, e
                                        );
                                    }
                                }
                            }
                            None => {
                                match network.lock().await.get(&packet.source())? {
                                    (Some(peer_node), _) => {
                                        let mut new_peer_node = peer_node.clone();
                                        // Update hole address with the new one.
                                        new_peer_node.public_addr_hole = peer_public_addr_hole;

                                        // When this node is restarted and the peer has been connected before, it will reconnnect again.
                                        // In the case the peer's public key or nonce is changed, a user must execute the knock-request CLI command manually.
                                        gateway::send(
                                            main_sock,
                                            &gateway::packet::PacketBuilder::new()?
                                                .protocol(gateway::packet::Protocol::KnockRequest)?
                                                .source(config.private_ipv4)?
                                                .add_payload(
                                                    gateway::packet::KnockRequestPacketBuilder::new()?
                                                        .private_ipv4(packet.source())?
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
                                        .await?
                                    }
                                    (None, _) => {
                                        // peer not found in the network.
                                        log::warn!("Peer not found in the local cache. Execute knock-request CLI command. peer_private={}", &packet.source());
                                    }
                                }
                            }
                        }
                    }
                    prefix => {
                        log::warn!("Ignore unknown packet. prefix={:?}", prefix);
                    }
                }
            }
            Err(e) => {
                log::debug!("Could not read the UDP packet. reason={}", e);
                continue;
            }
        }
    }
}
