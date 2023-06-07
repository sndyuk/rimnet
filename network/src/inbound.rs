use anyhow::Result;
use std::net::Ipv4Addr;

use crate::device::NetworkDevice;
use futures::StreamExt;
use lib::gateway;
use std::sync::Arc;
use std::{collections::HashMap, net::SocketAddr};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tokio_util::codec::FramedRead;
use tracing as log;
use tun::{AsyncDevice, IntoAddress, TunPacketCodec};

use super::config::*;
use super::state::*;

use lazy_static::lazy_static;
use snow::params::NoiseParams;
use snow::{Builder as HandshakeBuilder, HandshakeState};

lazy_static! {
    pub static ref NOISE_PARAMS: NoiseParams = "Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

static SYNC_PACKET: [u8; 2] = [0x00, 0x01];

pub async fn run(config: NetworkConfig) -> Result<()> {
    let mut device = NetworkDevice::<FramedRead<ReadHalf<AsyncDevice>, TunPacketCodec>>::create(
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
    let network = Arc::new(Mutex::new(Network::new(format!(
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
            match listen_inbound_incomming(&mut device.writer, &tunnel_sock_addr, network, &config)
                .await
            {
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
            match listen_inbound_outgoing(&mut device.reader, &tunnel_sock_addr, network, &config)
                .await
            {
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

// Consume messages comming from the tunnel
async fn listen_inbound_incomming(
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
                    log::warn!("[Inbound / incomming] Ignore the invalid packet");
                    continue;
                }
                match packet.protocol() {
                    gateway::packet::Protocol::KnockRequest => {
                        log::debug!("[Inbound / incomming] Received a knock request");
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

                                log::trace!(
                                    "[Inbound / incomming] knock packet: {:?}",
                                    knock_packet
                                );
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
                                log::debug!(
                                    "[Inbound / incomming] sent knock request. peer_public={}",
                                    peer_public_addr
                                );
                            }
                            Err(e) => {
                                log::warn!(
                                    "[Inbound / incomming] Knock request failed. reason={}",
                                    e
                                );
                            }
                        }
                    }
                    gateway::packet::Protocol::Knock => {
                        log::debug!("[Inbound / incomming] Received a knock");
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

                                log::trace!(
                                    "[Inbound / incomming] handshake packet: {:?}",
                                    handshake_packet
                                );
                                let mut hs = HandshakeBuilder::new(NOISE_PARAMS.clone())
                                    .local_private_key(&config.private_key)
                                    .remote_public_key(&knock_packet.public_key().as_ref())
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
                                    "[Inbound / incomming] Sent handshake request. peer_private={}, peer_public={}",
                                    packet.source(),
                                    peer_public_addr_hole
                                );

                                log::info!(
                                    "[Inbound / incomming] Knock accepted: peer_private={}",
                                    packet.source(),
                                );
                            }
                            Err(e) => {
                                log::warn!(
                                    "[Inbound / incomming] Knock failed. peer_public={}, reason={}",
                                    peer_public_addr_hole,
                                    e
                                );
                            }
                        };
                    }
                    gateway::packet::Protocol::Handshake => {
                        log::debug!("[Inbound / incomming] Start handshake");
                        log::trace!("packet: {:?}", packet);

                        let mut hs = HandshakeBuilder::new(NOISE_PARAMS.clone())
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
                                log::debug!(
                                    "[Inbound / incomming] Handshake received. peer_public={}",
                                    peer_public_addr
                                );

                                let handshake_accept_packet =
                                    gateway::packet::HandshakeAcceptPacketBuilder::new()?
                                        .nonce(handshake_packet.nonce())?
                                        .public_ipv4(config.public_ipv4)?
                                        .public_port(config.public_port)?
                                        .public_key(&config.public_key)?
                                        .build()?;

                                log::trace!(
                                    "[Inbound / incomming] handshake_accept packet: {:?}",
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
                                    handshake_packet.public_key().to_vec(),
                                    ts.clone(),
                                )?;

                                let peer = Peer {
                                    ts: ts.clone(),
                                    public_addr: peer_public_addr,
                                    public_addr_hole: peer_public_addr_hole,
                                };
                                if let Some(old_peer) = peers_cache.insert(packet.source(), peer) {
                                    log::debug!(
                                        "[Inbound / incomming] Update old peer state. old peer_public={}, new peer_public={}",
                                        old_peer.public_addr_hole, peer_public_addr_hole
                                    );
                                };
                                log::info!(
                                    "[Inbound / incomming] Session established: peer_private={}, peer_public={}, peer_public_hole={}",
                                    packet.source(),
                                    peer_public_addr,
                                    peer_public_addr_hole,
                                );
                            }
                            Err(e) => {
                                log::warn!(
                                    "[Inbound / incomming] Handshake failed. peer_public={}, reason={}",
                                    peer_public_addr_hole,
                                    e
                                );
                            }
                        }
                    }
                    gateway::packet::Protocol::HandshakeAccept => {
                        log::debug!("[Inbound / incomming] Start handshake accept");
                        log::trace!("packet: {:?}", packet);

                        let hs = hs_cache.remove(&packet.source());
                        if hs.is_none() {
                            log::debug!(
                                "[Inbound / incomming] Invalid packet. Required knock packet first."
                            );
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
                                log::debug!(
                                    "[Inbound / incomming] Handshake accepted. peer_public={}",
                                    peer_public_addr
                                );

                                let ts = Arc::new(hs.into_stateless_transport_mode()?);
                                let mut network = network.lock().await;
                                network.confirm_node(
                                    &packet.source(),
                                    handshake_accept_packet.nonce(),
                                    peer_public_addr,
                                    peer_public_addr_hole,
                                    handshake_accept_packet.public_key().to_vec(),
                                    ts.clone(),
                                )?;

                                let peer = Peer {
                                    ts: ts.clone(),
                                    public_addr: peer_public_addr,
                                    public_addr_hole: peer_public_addr_hole,
                                };
                                if let Some(old_peer) = peers_cache.insert(packet.source(), peer) {
                                    log::debug!(
                                        "[Inbound / incomming] Update old peer state. old peer_public={}, new peer_public={}",
                                        old_peer.public_addr_hole, peer_public_addr_hole
                                    );
                                };
                                log::info!(
                                    "[Inbound / incomming] Session established: peer_private={}, peer_public={}, peer_public_hole={}",
                                    packet.source(),
                                    peer_public_addr,
                                    peer_public_addr_hole,
                                );

                                // It's just a signal to the outgoing channel to resync the new peer state.
                                gateway::send_raw(
                                    main_sock,
                                    SYNC_PACKET,
                                    &format!("{}:255", packet.source()).parse::<SocketAddr>()?,
                                )
                                .await?;
                            }
                            Err(e) => {
                                log::warn!(
                                    "[Inbound / incomming] Handshake accept failed. peer_public={}, reason={}",
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
                                            "[Inbound / incomming] Could not extract the payload. Retry handshake manually. peer_public={}. reason={}",
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
                                            &main_sock,
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
                                        log::warn!("[inbound / incomming] Peer not found in the local cache. Execute knock-request CLI command. peer_private={}", &packet.source());
                                    }
                                }
                            }
                        }
                    }
                    prefix => {
                        log::warn!(
                            "[Inbound / incomming] Ignore unknown packet. prefix={:?}",
                            prefix
                        );
                    }
                }
            }
            Err(e) => {
                log::debug!(
                    "[Inbound / incomming] Could not read the UDP packet. reason={}",
                    e
                );
                continue;
            }
        }
    }
}

// Transfer message from the TUN device to the remote peer
async fn listen_inbound_outgoing(
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
                        log::trace!("[Inbound / outgoing] Drop the packet. protocol=IPv6");
                        continue;
                    }
                    _ => {
                        log::warn!(
                            "[Inbound / outgoing] Drop the packet. protocol=unknown, data={:?}",
                            raw_packet_bytes
                        );
                        continue;
                    }
                };

                let peer_private_ipv4 = payload_packet.destination();
                if raw_packet_bytes.len() == 30 // Includes IP and UDP packet header
                    && raw_packet_bytes[28..30] == SYNC_PACKET
                {
                    log::trace!(
                        "[Inbound / outgoing] Sync the peer state of '{}'",
                        peer_private_ipv4
                    );
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
                    log::trace!(
                        "[Inbound / outgoing] Drop the multicast packet. {}",
                        peer_private_ipv4
                    );
                    continue;
                }
                if peer_private_ipv4.is_broadcast() {
                    // TODO: It should be configurable whether skip or ingest. Need any concrete usecase.
                    log::trace!(
                        "[Inbound / outgoing] Drop the broadcast packet. {}",
                        peer_private_ipv4
                    );
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
                                "[Inbound / outgoing] Peer not found. Wait for a sec or manually connect to the peer using CLI(knock-request command). peer_privat_ipv4={}",
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
                                "[Inbound / outgoing] Peer not found. Ask the peer to the connected {} neighbor(s). peer_privat_ipv4={}",
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

                                log::trace!(
                                    "[Inbound / outgoing] query packet: {:?}",
                                    query_packet
                                );
                                gateway::send(&main_sock, &packet, &peer.public_addr_hole).await?;
                            }
                            continue;
                        }
                    }
                }
                log::debug!("[Inbound / outgoing] Transferring the packet");
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
                            "[Inbound / outgoing] Sent packet. peer_private={}, peer_public={}",
                            peer_private_ipv4,
                            peer.public_addr_hole
                        );
                        log::trace!(
                            "[Inbound / outgoing] payload: {:?} (encrypted={:?})",
                            payload_packet,
                            &buf[..encrypted_packet_len],
                        );
                    }
                    Err(e) => {
                        log::warn!(
                                "[Inbound / outgoing] Could not send the data. peer_private={}, reason={}",
                                peer_private_ipv4,
                                e
                            );
                    }
                }
            }
            Some(Err(e)) => {
                log::warn!(
                    "[Inbound / outgoing] Could not read the UDP packet. reason={}",
                    e
                );
                continue;
            }
            None => {
                log::warn!("[Inbound / outgoing] Could not read the UDP packet. reason=unknown");
                continue;
            }
        }
    }
}
