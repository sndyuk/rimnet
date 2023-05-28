use anyhow::{anyhow, Result};
use std::net::Ipv4Addr;

use crate::device::NetworkDevice;
use futures::StreamExt;
use lib::gateway;
use snow::Builder as HandshakeBuilder;
use std::sync::Arc;
use std::{collections::HashMap, net::SocketAddr};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tokio_util::codec::FramedRead;
use tracing as log;
use tun::{AsyncDevice, TunPacketCodec};

use super::config::*;
use super::state::*;

use lazy_static::lazy_static;
use snow::params::NoiseParams;

lazy_static! {
    // TODO Be customizable
    pub static ref NOISE_PARAMS: NoiseParams = "Noise_N_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

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
        let private_key = config.private_key.clone();
        let public_key = config.public_key.clone();
        let network = network.clone();
        async move {
            match listen_inbound_incomming(
                &mut device.writer,
                &tunnel_sock_addr,
                network,
                &private_key,
                &public_key,
                &config.private_ipv4,
                &config.external_public_ipv4,
                config.external_public_port,
            )
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
        let private_key = config.private_key.clone();
        let public_key = config.public_key.clone();
        let network = network.clone();
        async move {
            match listen_inbound_outgoing(
                &mut device.reader,
                &tunnel_sock_addr,
                network,
                &private_key,
                &public_key,
                &config.private_ipv4,
                &config.external_public_ipv4,
                config.external_public_port,
            )
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
    private_key: &Vec<u8>,
    public_key: &Vec<u8>,
    private_ipv4: &Ipv4Addr,
    external_public_ipv4: &Ipv4Addr,
    external_public_port: u16,
) -> Result<()> {
    // Key: private IPv4 of the peer
    let mut peers_cache: HashMap<Ipv4Addr, Peer> = HashMap::new();
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
                                let peer_public_addr = format!(
                                    "{}:{}",
                                    knock_request_packet.public_ipv4(),
                                    knock_request_packet.public_port()
                                )
                                .parse::<SocketAddr>()?;
                                let reserved_node =
                                    network.lock().await.reserve_node(peer_public_addr)?;

                                // Send knock packet
                                let knock_packet = gateway::packet::KnockPacketBuilder::new()?
                                    .private_ipv4(private_ipv4.clone())?
                                    .nonce(reserved_node.nonce)?
                                    .public_ipv4(external_public_ipv4.clone())?
                                    .public_port(external_public_port)?
                                    .public_key(public_key)?
                                    .build()?;

                                log::trace!(
                                    "[Inbound / incomming] knock packet: {:?}",
                                    knock_packet
                                );
                                let packet = gateway::packet::PacketBuilder::new()?
                                    .protocol(gateway::packet::Protocol::Knock)?
                                    .add_payload(knock_packet.as_ref())?
                                    .build()?;

                                gateway::send(main_sock, &packet, &peer_public_addr).await?;
                                log::debug!(
                                    "[Inbound / incomming] sent knock request. peer_public={}",
                                    peer_public_addr
                                );
                            }
                            Err(e) => {
                                log::warn!(
                                    "[Inbound / incomming] Knock request failed. peer_public={}, reason={}",
                                    peer_public_addr_hole,
                                    e
                                );
                            }
                        }
                    }
                    gateway::packet::Protocol::Knock => {
                        log::debug!("[Inbound / incomming] Received a knock");
                        match packet.to_knock() {
                            Ok(knock_packet) => {
                                let peer_public_addr = format!(
                                    "{}:{}",
                                    knock_packet.public_ipv4(),
                                    knock_packet.public_port(),
                                )
                                .parse::<SocketAddr>()?;

                                let reserved_node =
                                    network.lock().await.reserve_node(peer_public_addr)?;

                                // TODO Confirm the peer node after vaidating it with the owner.

                                // Start handshake
                                let handshake_packet =
                                    gateway::packet::HandshakePacketBuilder::new()?
                                        .private_ipv4(private_ipv4.clone())?
                                        .nonce(knock_packet.nonce())?
                                        .public_ipv4(external_public_ipv4.clone())?
                                        .public_port(external_public_port)?
                                        .public_key(public_key)?
                                        .build()?;

                                log::trace!(
                                    "[Inbound / incomming] handshake packet: {:?}",
                                    handshake_packet
                                );
                                let mut noise = HandshakeBuilder::new(NOISE_PARAMS.clone())
                                    .local_private_key(&private_key)
                                    .remote_public_key(&knock_packet.public_key().as_ref())
                                    .build_initiator()?;

                                let mut buf = [0u8; 127];
                                let handshake_len =
                                    noise.write_message(handshake_packet.as_ref(), &mut buf)?;
                                assert!(handshake_len <= 127);

                                let packet = gateway::packet::PacketBuilder::new()?
                                    .protocol(gateway::packet::Protocol::Handshake)?
                                    .add_payload(&buf[..handshake_len])?
                                    .build()?;
                                gateway::send(main_sock, &packet, &peer_public_addr).await?;
                                log::debug!(
                                    "[Inbound / incomming] sent handshake request. peer_private={}, peer_public={}",
                                    knock_packet.private_ipv4(),
                                    peer_public_addr_hole
                                );

                                log::info!(
                                    "[Inbound / incomming] Knock accepted: peer_private={}, peer_public={}",
                                    knock_packet.private_ipv4(),
                                    peer_public_addr_hole
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
                        if let Err(e) = receive_handshake(
                            &network,
                            &private_key,
                            &mut peers_cache,
                            peer_public_addr_hole,
                            &mut packet,
                        )
                        .await
                        {
                            log::warn!(
                                "[Inbound / incomming] Ignore the handshake error. cause={}",
                                e
                            );
                        };
                    }
                    gateway::packet::Protocol::TcpIp => {
                        match packet.to_tcpip() {
                            Ok(tcpip_packet) => {
                                match peers_cache.get_mut(&tcpip_packet.source_ipv4()) {
                                    Some(_) => {
                                        log::trace!(
                                            "Accept the TcpIp packet: {:?}",
                                            tcpip_packet.payload().as_ref()
                                        );
                                        // Afer the handshake
                                        tun_writer
                                            .write_all(tcpip_packet.payload().as_ref())
                                            .await?;
                                    }
                                    None => {
                                        let peer_private_ipv4 = tcpip_packet.source_ipv4();
                                        log::info!(
                                            "[Inbound / incomming] Peer not found. Trying to reconnect. peer_private={}",
                                            peer_private_ipv4
                                        );
                                        match network.lock().await.get(&peer_private_ipv4) {
                                            Ok(Some(peer_node)) => {
                                                let mut new_peer_node = peer_node.clone();
                                                // Update hole address with the new one.
                                                new_peer_node.public_addr_hole = peer_public_addr_hole;

                                                retry_handshake(
                                                    &main_sock,
                                                    &mut peers_cache,
                                                    &private_ipv4,
                                                    &external_public_ipv4,
                                                    external_public_port,
                                                    &public_key,
                                                    &private_key,
                                                    &peer_private_ipv4,
                                                    &new_peer_node,
                                                )
                                                .await?
                                            }
                                            Ok(None) => {
                                                // peer not found in the network.
                                                log::warn!("[inbound / incomming] Peer not found in the local cache. Execute knock-request CLI command. peer_private={}", peer_private_ipv4);
                                            }
                                            Err(e) => panic!("[inbound / incomming] Network state is broken. cause={}", e),
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!(
                            "[Inbound / incomming] Could not extract the payload. Retry handshake manually. peer_public={}. reason={}",
                            peer_public_addr_hole, e);
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

async fn receive_handshake(
    network: &Arc<Mutex<Network>>,
    private_key: &Vec<u8>,
    peers: &mut HashMap<Ipv4Addr, Peer>,
    peer_public_addr_hole: SocketAddr,
    packet: &mut gateway::packet::Packet<impl AsRef<[u8]>>,
) -> Result<()> {
    let mut hs = HandshakeBuilder::new(NOISE_PARAMS.clone())
        .local_private_key(&private_key)
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
            let mut network = network.lock().await;
            network.confirm_node(
                &handshake_packet.private_ipv4(),
                handshake_packet.nonce(),
                peer_public_addr,
                peer_public_addr_hole,
                handshake_packet.public_key().to_vec(),
            )?;

            if let Some(old_peer) = peers.insert(
                handshake_packet.private_ipv4(),
                Peer {
                    ts: Box::new(hs.into_transport_mode()?),
                    public_addr: peer_public_addr,
                    public_addr_hole: peer_public_addr_hole,
                },
            ) {
                log::debug!(
                    "[Inbound / incomming] Update old peer state. old peer_public={}, new peer_public={}",
                    old_peer.public_addr_hole, peer_public_addr_hole
                );
            };
            log::info!(
                "[Inbound / incomming] Session established: peer_private={}, peer_public={}",
                handshake_packet.private_ipv4(),
                peer_public_addr
            );
            Ok(())
        }
        Err(e) => {
            log::warn!(
                "[Inbound / incomming] Handshake failed. peer_public={}, reason={}",
                peer_public_addr_hole,
                e
            );
            Err(anyhow!(e))
        }
    }
}

// When this node is restarted and the peer has been connected before, it will reconnnect again.
// In the case the peer's public key or nonce is changed, a user must execute the knock-request CLI command manually.
async fn retry_handshake(
    main_sock: &UdpSocket,
    peers: &mut HashMap<Ipv4Addr, Peer>,
    private_ipv4: &Ipv4Addr,
    external_public_ipv4: &Ipv4Addr,
    external_public_port: u16,
    public_key: &Vec<u8>,
    private_key: &Vec<u8>,
    peer_private_ipv4: &Ipv4Addr,
    peer_node: &Node,
) -> Result<()> {
    log::debug!(
        "[Inbound / incomming] Start handshake. peer_public={}",
        peer_node.public_addr
    );
    let handshake_packet = gateway::packet::HandshakePacketBuilder::new()?
        .private_ipv4(private_ipv4.clone())?
        .nonce(peer_node.nonce)?
        .public_ipv4(external_public_ipv4.clone())?
        .public_port(external_public_port)?
        .public_key(public_key.to_vec())?
        .build()?;

    log::trace!("handshake packet: {:?}", handshake_packet);

    let mut hs = HandshakeBuilder::new(NOISE_PARAMS.clone())
        .local_private_key(&private_key)
        .remote_public_key(&peer_node.public_key)
        .build_initiator()?;

    let mut buf = [0u8; 65535];
    let handshake_len = hs.write_message(handshake_packet.as_ref(), &mut buf)?;
    assert!(handshake_len <= 127);

    let packet = gateway::packet::PacketBuilder::new()?
        .protocol(gateway::packet::Protocol::Handshake)?
        .add_payload(&buf[..handshake_len])?
        .build()?;

    match gateway::send(main_sock, &packet, &peer_node.public_addr).await {
        Ok(_) => {
            log::debug!(
                "[Inbound / incomming] Session will be established: peer_private={}, peer_public={}",
                peer_private_ipv4, peer_node.public_addr
            );

            if let Some(old_peer) = peers.insert(
                peer_private_ipv4.clone(),
                Peer {
                    ts: Box::new(hs.into_transport_mode()?),
                    public_addr: peer_node.public_addr,
                    public_addr_hole: peer_node.public_addr_hole,
                },
            ) {
                log::debug!(
                    "[Inbound / incomming] Update old peer state. old peer_public={}, new peer_public={}",
                    old_peer.public_addr_hole, peer_node.public_addr_hole
                );
            };
            Ok(())
        }
        Err(e) => {
            log::warn!(
                "[Inbound / incomming] Handshake failed. peer_private={}, reason={}",
                peer_private_ipv4,
                e
            );
            Err(e)
        }
    }
}

// Transfer message from the TUN device to the remote peer
async fn listen_inbound_outgoing(
    tun_reader: &mut FramedRead<ReadHalf<AsyncDevice>, TunPacketCodec>,
    main_sock: &UdpSocket,
    network: Arc<Mutex<Network>>,
    private_key: &Vec<u8>,
    public_key: &Vec<u8>,
    private_ipv4: &Ipv4Addr,
    external_public_ipv4: &Ipv4Addr,
    external_public_port: u16,
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

                match peers_cache.get_mut(&peer_private_ipv4) {
                    // Received packet to a registered peer
                    Some(peer) => {
                        log::debug!("[Inbound / outgoing] Transferring the packet");

                        // Wrap the raw packet
                        let packet = gateway::packet::PacketBuilder::new()?
                            .protocol(gateway::packet::Protocol::TcpIp)?
                            .add_payload(
                                gateway::packet::TcpIpPacketBuilder::new()?
                                    .source_ipv4(private_ipv4.clone())?
                                    .add_payload(payload_packet.as_ref())?
                                    .build()?
                                    .as_ref(),
                            )?
                            .build()?;

                        match gateway::send(main_sock, &packet, &peer.public_addr).await {
                            Ok(_) => {
                                log::debug!(
                                        "[Inbound / outgoing] Sent packet. peer_private={}, peer_public={}",
                                        peer_private_ipv4, peer.public_addr
                                    );
                                log::trace!("[Inbound / outgoing] payload: {:?}", payload_packet);
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
                    // In the case of an unknown peer, search for the public address using the target's private address.
                    None => {
                        let network = network.lock().await;
                        let peer_node = match network.get(&peer_private_ipv4)? {
                            // The peer is found in the private network
                            Some(v) => v,

                            // Not found in the private network.
                            // Someone in the network may know the peer's public address. Try to find it.
                            None => {
                                log::debug!(
                                    "[Inbound / outgoing] The target peer({}) not found in the local cache. Send query request to the connected {} peer(s).",
                                    peer_private_ipv4, peers_cache.len()
                                );
                                // TODO tests
                                // Query the peer's info to other peers and knock to the peer.
                                let query_packet = gateway::packet::QueryPacketBuilder::new()?
                                    .private_ipv4(private_ipv4.clone())?
                                    .public_ipv4(external_public_ipv4.clone())?
                                    .public_port(external_public_port)?
                                    .target_private_ipv4(peer_private_ipv4)?
                                    .public_key(&public_key)?
                                    .build()?;

                                // Multicast the knock request.
                                for (_, peer) in peers_cache.iter() {
                                    let packet = gateway::packet::PacketBuilder::new()?
                                        .protocol(gateway::packet::Protocol::Query)?
                                        .add_payload(query_packet.as_ref())?
                                        .build()?;

                                    log::trace!(
                                        "[Inbound / outgoing] query packet: {:?}",
                                        query_packet
                                    );
                                    gateway::send(&main_sock, &packet, &peer.public_addr).await?;
                                }
                                continue;
                            }
                        };

                        // When this node is restarted and the peer has been connected before, it will reconnnect again.
                        // In the case the peer's public key or nonce is changed, a user must execute the knock-request CLI command manually.
                        retry_handshake(
                            &main_sock,
                            &mut peers_cache,
                            &private_ipv4,
                            &external_public_ipv4,
                            external_public_port,
                            &public_key,
                            &private_key,
                            &peer_private_ipv4,
                            &peer_node,
                        )
                        .await?
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
