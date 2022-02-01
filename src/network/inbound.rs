use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr};

use crate::gateway;
use crate::network::device::NetworkDevice;
use futures::StreamExt;
use packet::{self, Packet};
use snow::Builder as HandshakeBuilder;
use std::sync::Arc;
use std::{collections::HashMap, net::SocketAddr};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::UdpSocket;
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
    log::info!(
        "The tunnel listening on {:?}",
        tunnel_sock_addr.local_addr()?
    );

    // Prepare the network
    let network = Arc::new(Mutex::new(Network::new()?));

    // Inbound incomming loop
    let inbound_incomming_loop = tokio::spawn({
        let tunnel_sock_addr = tunnel_sock_addr.clone();
        let network = network.clone();
        let private_key = config.private_key.clone();
        async move {
            match listen_inbound_incomming(
                &mut device.writer,
                &tunnel_sock_addr,
                network,
                private_key,
            )
            .await
            {
                Ok(_) => true,
                Err(e) => {
                    log::error!(
                        "[Inbound / incomming] Could not recover the error. reason={}",
                        e
                    );
                    false
                }
            }
        }
    });
    log::debug!("[Inbound / incomming] Main loop started");

    // Inbound outging loop
    let inbound_outgoing_loop = tokio::spawn({
        let tunnel_sock_addr = tunnel_sock_addr.clone();
        let private_key = config.private_key.clone();
        let network = network.clone();
        async move {
            match listen_inbound_outgoing(
                &mut device.reader,
                &tunnel_sock_addr,
                config.public_port,
                network,
                private_key,
            )
            .await
            {
                Ok(_) => true,
                Err(e) => {
                    log::error!(
                        "[Inbound / outgoing] Could not recover the error. reason={}",
                        e
                    );
                    false
                }
            }
        }
    });
    log::debug!("[Inbound / outgoing] Main loop started");

    inbound_incomming_loop.await?;
    inbound_outgoing_loop.await?;
    Ok(())
}

async fn listen_inbound_incomming(
    tun_writer: &mut WriteHalf<AsyncDevice>,
    main_sock: &UdpSocket,
    network: Arc<Mutex<Network>>,
    private_key: Vec<u8>,
) -> Result<()> {
    // Key: public IPv4 of the peer
    let mut peers_cache: HashMap<IpAddr, Peer> = HashMap::new();
    loop {
        match gateway::recv(main_sock).await {
            Ok((mut packet, peer_remote_addr)) => {
                if !packet.is_valid() {
                    log::warn!("[Inbound / incomming] Ignore the invalid packet");
                    continue;
                }
                match packet.protocol() {
                    gateway::packet::Protocol::Handshake => {
                        // Before the handshake. The first packet must be the handshake request.
                        log::debug!("[Inbound / incomming] Start handshake");
                        if receive_handshake(
                            &network,
                            &private_key,
                            &mut peers_cache,
                            peer_remote_addr,
                            &mut packet,
                        )
                        .await
                        .is_err()
                        {
                            log::debug!("[Inbound / incomming] Ignore the handshake error");
                        };
                    }
                    gateway::packet::Protocol::TcpIp => {
                        match peers_cache.get_mut(&peer_remote_addr.ip()) {
                            Some(peer) => {
                                // Afer the handshake
                                log::debug!("[Inbound / incomming] Decrypting the payload");
                                match packet.to_tcpip(peer.ts.as_mut()) {
                                    Ok(tcpip_packet) => {
                                        log::debug!("[Inbound / incomming] Message decrypted");
                                        tun_writer.write_all(tcpip_packet.payload()).await?;
                                    }
                                    Err(e) => {
                                        log::warn!(
                                    "[Inbound / incomming] Could not decrypt the payload. Retry handshake. peer_remote={}. reason={}",
                                    peer_remote_addr, e);
                                        log::warn!(
                                            "[Inbound / incomming] Ignore the handshake error"
                                        );
                                    }
                                }
                            }
                            None => {
                                log::info!(
                                    "[Inbound / incomming] Peer not found. Require handshake first."
                                );
                            }
                        }
                    }
                    gateway::packet::Protocol::Knock => {
                        log::debug!("[Inbound / incomming] Received a knock");
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
    peers: &mut HashMap<IpAddr, Peer>,
    peer_remote_addr: SocketAddr,
    packet: &mut gateway::packet::Packet<Vec<u8>>,
) -> Result<()> {
    let mut hs = HandshakeBuilder::new(NOISE_PARAMS.clone())
        .local_private_key(&private_key)
        .build_responder()?;
    match packet.to_handshake(&mut hs) {
        Ok(handshake_packet) => {
            log::debug!("[Inbound / incomming] Handshake scceeded");
            peers.insert(
                peer_remote_addr.ip(),
                Peer {
                    ts: Box::new(hs.into_transport_mode()?),
                    remote_addr: Box::new(peer_remote_addr),
                },
            );
            network.lock().await.put(
                &handshake_packet.source_ipv4(),
                peer_remote_addr.ip(),
                handshake_packet.public_key().to_vec(),
            );
            log::debug!(
                "[Inbound / incomming] Session established: peer_private={}, peer_remote={}",
                handshake_packet.source_ipv4(),
                peer_remote_addr
            );
            Ok(())
        }
        Err(e) => {
            log::warn!(
                "[Inbound / incomming] Handshake failed. peer_remote={}, reason={}",
                peer_remote_addr,
                e
            );
            Err(anyhow!(e))
        }
    }
}

async fn listen_inbound_outgoing(
    tun_reader: &mut FramedRead<ReadHalf<AsyncDevice>, TunPacketCodec>,
    main_sock: &UdpSocket,
    main_port: u16,
    network: Arc<Mutex<Network>>,
    private_key: Vec<u8>,
) -> Result<()> {
    let mut peers_cache: HashMap<Ipv4Addr, Peer> = HashMap::new();

    loop {
        match tun_reader.next().await {
            Some(Ok(raw_packet)) => {
                let raw_packet_bytes = raw_packet.get_bytes();
                let packet = match raw_packet_bytes[0] >> 4 {
                    4 => packet::ip::v4::Packet::unchecked(raw_packet_bytes),
                    6 => {
                        log::warn!(
                            "[Inbound / outgoing] Drop the packet. protocol=IPv6, data={:?}",
                            raw_packet_bytes
                        );
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
                let peer_private_addr = packet.destination();
                if peer_private_addr.is_multicast() || peer_private_addr.is_broadcast() {
                    // Skip multicast and broadcast packet.
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
                                    "[Inbound / outgoing] Drop the packet to the unknown peer. The peer must be registered in advance. peer_private_addr={}",
                                    peer_private_addr
                                );
                                continue;
                            }
                        };
                        let mut hs = HandshakeBuilder::new(NOISE_PARAMS.clone())
                            .local_private_key(&private_key)
                            .remote_public_key(&remote_node.public_key)
                            .build_initiator()?;

                        log::debug!("[Inbound / outgoing] Start handshake");
                        let peer_remote_addr = SocketAddr::new(remote_node.public_addr, main_port);
                        log::debug!("[Inbound / outgoing] peer_remote_addr={}", peer_remote_addr);
                        let mut buf = vec![0u8; 65535]; // TODO Recycle the huge buffer
                        let handshake_len = hs.write_message(&[], &mut buf)?;
                        match gateway::send(main_sock, &buf[..handshake_len], &peer_remote_addr)
                            .await
                        {
                            Ok(_) => {
                                log::debug!("[Inbound / outgoing] Handshake scceeded and sending the packet");
                                let mut ts = hs.into_transport_mode()?;
                                let len = ts.write_message(packet.as_ref(), &mut buf)?;
                                match gateway::send(main_sock, &buf[..len], &peer_remote_addr).await
                                {
                                    Ok(_) => {
                                        log::debug!(
                                                    "[Inbound / outgoing] Session established: peer_private={}, peer_remote={}",
                                                    peer_private_addr, peer_remote_addr
                                                );
                                        peers_cache.insert(
                                            peer_private_addr,
                                            Peer {
                                                ts: Box::new(ts),
                                                remote_addr: Box::new(peer_remote_addr),
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
                        let payload = packet.payload();
                        if payload.len() == 0 {
                            log::debug!(
                                "[Inbound / outgoing] Ignore the packet. peer_private_addr={}",
                                peer_private_addr
                            );
                            continue;
                        }
                        let buf = &mut [0u8; 65535]; // TODO Recycle the huge buffer
                        let len = peer
                            .ts
                            .as_mut()
                            .write_message(raw_packet.get_bytes(), buf)?;
                        match gateway::send(main_sock, &buf[..len], &peer.remote_addr).await {
                            Ok(_) => {
                                log::debug!(
                                        "[Inbound / outgoing] Sent packet. peer_private={}, peer_public={}",
                                        peer_private_addr, peer.remote_addr
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
