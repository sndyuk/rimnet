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
    let network = Arc::new(Mutex::new(Network::new()?));

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
                    gateway::packet::Protocol::Knock => {
                        log::debug!("[Inbound / incomming] Received a knock");
                        match packet.to_knock() {
                            Ok(knock_packet) => {
                                // Start handshake
                                let peer_public_addr = format!(
                                    "{}:{}",
                                    knock_packet.public_ipv4(),
                                    knock_packet.public_port(),
                                )
                                .parse::<SocketAddr>()?;
                                let handshake_packet =
                                    gateway::packet::HandshakePacketBuilder::new()?
                                        .private_ipv4(private_ipv4.clone())?
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

                                network.lock().await.put(
                                    &knock_packet.private_ipv4(),
                                    peer_public_addr,
                                    peer_public_addr_hole,
                                    knock_packet.public_key(),
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
                        // Before the handshake. The first packet must be the handshake request.
                        log::debug!("[Inbound / incomming] Start handshake");
                        log::trace!("packet: {:?}", packet);
                        if receive_handshake(
                            &network,
                            &private_key,
                            &mut peers_cache,
                            peer_public_addr_hole,
                            &mut packet,
                        )
                        .await
                        .is_err()
                        {
                            log::debug!("[Inbound / incomming] Ignore the handshake error");
                        };
                    }
                    gateway::packet::Protocol::TcpIp => {
                        match packet.to_tcpip() {
                            Ok(tcpip_packet) => {
                                match peers_cache.get_mut(&tcpip_packet.source_ipv4()) {
                                    Some(_) => {
                                        // Afer the handshake
                                        log::debug!(
                                            "[Inbound / incomming] Message extracted: {:?}",
                                            tcpip_packet
                                        );
                                        tun_writer
                                            .write_all(tcpip_packet.payload().as_ref())
                                            .await?;
                                    }
                                    None => {
                                        log::info!(
                                            "[Inbound / incomming] Peer not found. Try knock."
                                        );
                                        let knock_packet =
                                            gateway::packet::KnockPacketBuilder::new()?
                                                .private_ipv4(private_ipv4.clone())?
                                                .public_ipv4(external_public_ipv4.clone())?
                                                .public_port(external_public_port)?
                                                .target_private_ipv4(
                                                    tcpip_packet.source_ipv4().clone(),
                                                )?
                                                .public_key(&public_key)?
                                                .build()?;
                                        log::trace!(
                                            "[Inbound / incomming] knock packet: {:?}",
                                            knock_packet
                                        );

                                        let packet = gateway::packet::PacketBuilder::new()?
                                            .protocol(gateway::packet::Protocol::Knock)?
                                            .add_payload(knock_packet.as_ref())?
                                            .build()?;

                                        gateway::send(&main_sock, &packet, &peer_public_addr_hole)
                                            .await?;
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
                "[Inbound / incomming] Handshake scceeded. peer_public: {}",
                peer_public_addr
            );

            peers.insert(
                handshake_packet.private_ipv4(),
                Peer {
                    ts: Box::new(hs.into_transport_mode()?),
                    public_addr: peer_public_addr,
                    public_addr_hole: peer_public_addr_hole,
                },
            );
            network.lock().await.put(
                &handshake_packet.private_ipv4(),
                peer_public_addr,
                peer_public_addr_hole,
                handshake_packet.public_key().to_vec(),
            );
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
                let raw_packet_bytes = raw_packet.get_bytes();
                let payload_packet = match raw_packet_bytes[0] >> 4 {
                    4 => packet::ip::v4::Packet::unchecked(raw_packet_bytes),
                    6 => {
                        log::debug!(
                            "[Inbound / outgoing] Drop the packet. protocol=IPv6, data={:?}",
                            raw_packet_bytes
                        );
                        continue;
                    }
                    _ => {
                        log::debug!(
                            "[Inbound / outgoing] Drop the packet. protocol=unknown, data={:?}",
                            raw_packet_bytes
                        );
                        continue;
                    }
                };
                let peer_private_addr = payload_packet.destination();
                if peer_private_addr.is_multicast() {
                    // TODO: It should be configurable whether skip or ingest. Need any concrete usecase.
                    log::trace!(
                        "[Inbound / outgoing] Drop the multicast packet. {}",
                        peer_private_addr
                    );
                    continue;
                }
                if peer_private_addr.is_broadcast() {
                    // TODO: It should be configurable whether skip or ingest. Need any concrete usecase.
                    log::trace!(
                        "[Inbound / outgoing] Drop the broadcast packet. {}",
                        peer_private_addr
                    );
                    continue;
                }
                match peers_cache.get_mut(&peer_private_addr) {
                    // Received packet to an unknown peer.
                    None => {
                        let network = network.lock().await;
                        let remote_node = match network.get(&peer_private_addr) {
                            Some(remote_public_key) => remote_public_key,
                            None => {
                                log::info!(
                                    "[Inbound / outgoing] The peer({}) not found. Try knock via a connected peer if any. Number of connected peers: {}. If any peer cannot reach the target peer, manually knock to the peer.",
                                    peer_private_addr, peers_cache.len()
                                );
                                // TODO: Query the peer's info to other peers and knock to the peer.
                                let knock_packet = gateway::packet::KnockPacketBuilder::new()?
                                    .private_ipv4(private_ipv4.clone())?
                                    .public_ipv4(external_public_ipv4.clone())?
                                    .public_port(external_public_port)?
                                    .target_private_ipv4(peer_private_addr)?
                                    .public_key(&public_key)?
                                    .build()?;

                                // Multicast the knock request.
                                for (_, peer) in peers_cache.iter() {
                                    let packet = gateway::packet::PacketBuilder::new()?
                                        .protocol(gateway::packet::Protocol::Knock)?
                                        .add_payload(knock_packet.as_ref())?
                                        .build()?;

                                    log::trace!(
                                        "[Inbound / outgoing] knock packet: {:?}",
                                        knock_packet
                                    );
                                    gateway::send(&main_sock, &packet, &peer.public_addr).await?;
                                }
                                continue;
                            }
                        };
                        log::debug!(
                            "[Inbound / outgoing] Start handshake. peer_public={}",
                            remote_node.public_addr
                        );
                        let handshake_packet = gateway::packet::HandshakePacketBuilder::new()?
                            .private_ipv4(private_ipv4.clone())?
                            .public_ipv4(external_public_ipv4.clone())?
                            .public_port(external_public_port)?
                            .public_key(public_key.to_vec())?
                            .build()?;

                        log::trace!("handshake packet: {:?}", handshake_packet);

                        let mut hs = HandshakeBuilder::new(NOISE_PARAMS.clone())
                            .local_private_key(&private_key)
                            .remote_public_key(&remote_node.public_key)
                            .build_initiator()?;

                        let mut buf = [0u8; 65535];
                        let handshake_len =
                            hs.write_message(handshake_packet.as_ref(), &mut buf)?;
                        assert!(handshake_len <= 127);

                        let packet = gateway::packet::PacketBuilder::new()?
                            .protocol(gateway::packet::Protocol::Handshake)?
                            .add_payload(&buf[..handshake_len])?
                            .build()?;

                        match gateway::send(main_sock, &packet, &remote_node.public_addr).await {
                            Ok(_) => {
                                log::debug!("[Inbound / outgoing] Handshake scceeded and sending the packet");
                                let tcpip_packet = gateway::packet::TcpIpPacketBuilder::new()?
                                    .source_ipv4(private_ipv4.clone())?
                                    .add_payload(payload_packet.as_ref())?
                                    .build()?;

                                let packet = gateway::packet::PacketBuilder::new()?
                                    .protocol(gateway::packet::Protocol::TcpIp)?
                                    .add_payload(tcpip_packet.as_ref())?
                                    .build()?;

                                match gateway::send(main_sock, &packet, &remote_node.public_addr)
                                    .await
                                {
                                    Ok(_) => {
                                        log::debug!(
                                            "[Inbound / outgoing] Session established: peer_private={}, peer_public={}",
                                            peer_private_addr, remote_node.public_addr
                                        );
                                        peers_cache.insert(
                                            peer_private_addr,
                                            Peer {
                                                ts: Box::new(hs.into_transport_mode()?),
                                                public_addr: remote_node.public_addr,
                                                public_addr_hole: remote_node.public_addr_hole,
                                            },
                                        );
                                    }
                                    Err(e) => {
                                        log::warn!("[Inbound / outgoing] Could not send the packet. reason={}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("[Inbound / outgoing] Handshake failed. peer_private={}, reason={}", peer_private_addr, e);
                            }
                        }
                    }
                    // Received packet to a registered peer
                    Some(peer) => {
                        log::debug!("[Inbound / outgoing] Sending the packet");
                        let tcpip_packet = gateway::packet::TcpIpPacketBuilder::new()?
                            .source_ipv4(private_ipv4.clone())?
                            .add_payload(payload_packet.as_ref())?
                            .build()?;

                        let packet = gateway::packet::PacketBuilder::new()?
                            .protocol(gateway::packet::Protocol::TcpIp)?
                            .add_payload(tcpip_packet.as_ref())?
                            .build()?;

                        match gateway::send(main_sock, &packet, &peer.public_addr).await {
                            Ok(_) => {
                                log::debug!(
                                        "[Inbound / outgoing] Sent packet. peer_private={}, peer_public={}",
                                        peer_private_addr, peer.public_addr
                                    );
                            }
                            Err(e) => {
                                log::warn!(
                                        "[Inbound / outgoing] Could not send the data. peer_private={}, reason={}",
                                        peer_private_addr,
                                        e
                                    );
                            }
                        }
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
