extern crate base64;

use anyhow::{anyhow, Result};
use clap::Parser;
use env_logger::{self, Env};
use futures::StreamExt;
use lazy_static::lazy_static;
use log;
use packet::{self, Packet};
use snow::{params::NoiseParams, Builder, TransportState};
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::{collections::HashMap, net::SocketAddr};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::codec::FramedRead;
use tun::{AsyncDevice, TunPacketCodec};

mod gateway;
mod inbound;

lazy_static! {
    static ref PARAMS: NoiseParams = "Noise_N_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

#[derive(Parser)]
#[clap()]
struct Opts {
    #[clap(short = 'n', long)]
    tun_device_name: String,
    #[clap(short, long, default_value = "7891")]
    port: u16,
    #[clap(short, long, default_value = "1500")]
    mtu: i32,
    #[clap(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts: Opts = Opts::parse();

    // Configure logger
    env_logger::builder()
        .parse_env(
            Env::default().filter_or("RIMNET_LOG", if opts.verbose { "DEBUG" } else { "INFO" }),
        )
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .init();

    // Start the inbound network
    let inbound = inbound::run(&opts.tun_device_name, opts.mtu).await?;
    let (inbound_reader, mut inbound_writer) = tokio::io::split(inbound);
    let codec = TunPacketCodec::new(true, opts.mtu);
    let mut frame_inbound_reader = FramedRead::new(inbound_reader, codec);

    // Listen the tunnel(encrypted payload <==> raw payload) traffic port
    let tunnel_sock_addr = Arc::new(UdpSocket::bind(format!("127.0.0.1:{}", opts.port)).await?);
    log::info!(
        "The tunnel listening on {:?}",
        tunnel_sock_addr.local_addr()?
    );

    // Prepare keypair for Noise
    let keypair = Builder::new(PARAMS.clone()).generate_keypair()?;
    log::info!("public key: {:?}", base64::encode(&keypair.public));

    // Prepare public keys
    let public_keys = Arc::new(Mutex::new(PrivateNet { db: HashMap::new() }));

    // Inbound incomming loop
    let inbound_incomming_loop = tokio::spawn({
        let tunnel_sock_addr = tunnel_sock_addr.clone();
        let public_keys = public_keys.clone();
        let private_key = keypair.private.clone();
        async move {
            match listen_inbound_incomming(
                &mut inbound_writer,
                &tunnel_sock_addr,
                public_keys,
                private_key,
            )
            .await
            {
                Ok(_) => true,
                Err(e) => {
                    log::error!(
                        "[Inbound / incomming] Could not recover the error. reason={:?}",
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
        let private_key = keypair.private.clone();
        let public_keys = public_keys.clone();
        async move {
            match listen_inbound_outgoing(
                &mut frame_inbound_reader,
                &tunnel_sock_addr,
                opts.port,
                public_keys,
                private_key,
            )
            .await
            {
                Ok(_) => true,
                Err(e) => {
                    log::error!(
                        "[Inbound / outgoing] Could not recover the error. reason={:?}",
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

struct PrivateNet {
    db: HashMap<Ipv4Addr, PrivateNode>,
}

struct PrivateNode {
    public_addr: IpAddr,
    public_key: Vec<u8>,
}

trait PrivateNetRegistry {
    fn get(&self, private_addr: &Ipv4Addr) -> Option<&PrivateNode>;
    fn put(&mut self, private_ipv4: &Ipv4Addr, public_addr: IpAddr, public_key: Vec<u8>);
}

impl PrivateNetRegistry for PrivateNet {
    fn get(&self, private_addr: &Ipv4Addr) -> Option<&PrivateNode> {
        self.db.get(private_addr)
    }
    fn put(&mut self, private_addr: &Ipv4Addr, public_addr: IpAddr, public_key: Vec<u8>) {
        self.db.insert(
            private_addr.clone(),
            PrivateNode {
                public_addr,
                public_key,
            },
        );
    }
}

struct Peer {
    ts: Box<TransportState>,
    buf: Vec<u8>,
    remote_addr: Box<SocketAddr>,
}

async fn listen_inbound_incomming(
    tun_writer: &mut WriteHalf<AsyncDevice>,
    main_sock: &UdpSocket,
    private_net: Arc<Mutex<PrivateNet>>,
    private_key: Vec<u8>,
) -> Result<()> {
    // Key: public IPv4 of the peer
    let mut peers: HashMap<IpAddr, Peer> = HashMap::new();

    /*
                                    let mut pos = 0;
                                for i in 0..payload.len() {
                                    if (payload[i] as char) == '\n' {
                                        pos = i;
                                        break;
                                    }
                                }
                                if pos == 0 {
                                    debug!(
                                        "[Inbound / outgoing] Ignore the packet. peer_private_addr={}",
                                        peer_private_addr
                                    );
                                    continue;
                                }
                                let remote_public_key = &payload[1..pos];
                                let handshake_message = &payload[pos..];
                                let mut hs = Builder::new(PARAMS.clone())
                                    .local_private_key(&private_key)
                                    .remote_public_key(remote_public_key)
                                    .build_responder()?;
    */
    loop {
        match gateway::recv(main_sock).await {
            Ok((encrypted_packet, peer_remote_addr)) => {
                match peers.get_mut(&peer_remote_addr.ip()) {
                    // Before the handshake. The first packet must be the handshake request.
                    None => {
                        log::debug!("[Inbound / incomming] Start handshake");
                        handshake(
                            &private_net,
                            &private_key,
                            &mut peers,
                            peer_remote_addr,
                            &encrypted_packet,
                        )
                        .await?;
                    }
                    // Afer the handshake
                    Some(peer) => {
                        log::debug!("[Inbound / incomming] Decrypting the payload");
                        match peer
                            .ts
                            .as_mut()
                            .read_message(encrypted_packet.as_ref(), &mut peer.buf)
                        {
                            Ok(len) => {
                                log::debug!("[Inbound / incomming] Message decrypted. len={}", len);
                                let mut packet = gateway::Packet::unchecked(peer.buf.clone());
                                packet.set_total_len(len as u16)?;
                                println!("{:?}", packet.payload());
                                tun_writer.write_all(&packet.payload()).await?;
                            }
                            Err(e) => {
                                log::warn!(
                                    "[Inbound / incomming] Could not decrypt the payload. Retry handshake. peer_remote={}. reason={:?}",
                                    peer_remote_addr, e
                                );
                                peers.remove(&peer_remote_addr.ip());
                                handshake(
                                    &private_net,
                                    &private_key,
                                    &mut peers,
                                    peer_remote_addr,
                                    &encrypted_packet,
                                )
                                .await?;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log::debug!(
                    "[Inbound / incomming] Could not read the UDP packet. {:?}",
                    e
                );
                continue;
            }
        }
    }
}

async fn handshake(
    private_net: &Arc<Mutex<PrivateNet>>,
    private_key: &Vec<u8>,
    peers: &mut HashMap<IpAddr, Peer>,
    peer_remote_addr: SocketAddr,
    encrypted_packet: &Vec<u8>,
) -> Result<()> {
    let mut hs = Builder::new(PARAMS.clone())
        .local_private_key(&private_key)
        .build_responder()?;

    let mut buf = vec![0u8; 65535];
    match hs.read_message(encrypted_packet.as_ref(), &mut buf) {
        Ok(payload_len) => {
            log::debug!("[Inbound / incomming] Handshake scceeded");
            let mut packet = gateway::Packet::unchecked(buf);
            packet.set_total_len(payload_len as u16)?;

            let remote_pubilc_key = packet.payload();
            private_net.lock().await.put(
                &packet.source_ipv4(),
                peer_remote_addr.ip(),
                Vec::from(remote_pubilc_key),
            );
            peers.insert(
                peer_remote_addr.ip(),
                Peer {
                    ts: Box::new(hs.into_transport_mode()?),
                    buf: vec![0u8; 65535],
                    remote_addr: Box::new(peer_remote_addr),
                },
            );
            log::debug!(
                "[Inbound / incomming] Session established: peer_private={}, peer_remote={}",
                packet.source_ipv4(),
                peer_remote_addr
            );
            Ok(())
        }
        Err(e) => {
            log::warn!(
                "[Inbound / incomming] Handshake failed. peer_remote={}, reason={:?}",
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
    private_net: Arc<Mutex<PrivateNet>>,
    private_key: Vec<u8>,
) -> Result<()> {
    let mut peers: HashMap<Ipv4Addr, Peer> = HashMap::new();
    loop {
        match tun_reader.next().await {
            Some(Ok(raw_packet)) => {
                let packet = packet::ip::v4::Packet::unchecked(raw_packet.get_bytes());
                let peer_private_addr = packet.source();
                let private_net = private_net.lock().await;
                match peers.get_mut(&peer_private_addr) {
                    // Received packet from a unknown peer
                    None => {
                        let remote_node = match private_net.get(&peer_private_addr) {
                            Some(remote_public_key) => remote_public_key,
                            None => {
                                log::warn!(
                                    "[Inbound / outgoing] Unknown client. peer_private_addr={}",
                                    peer_private_addr
                                );
                                continue;
                            }
                        };
                        let mut hs = Builder::new(PARAMS.clone())
                            .local_private_key(&private_key)
                            .remote_public_key(&remote_node.public_key)
                            .build_responder()?;

                        println!("test: {:?}", packet.payload());
                        log::debug!("[Inbound / outgoing] Start handshake");
                        let peer_remote_addr = SocketAddr::new(peer_private_addr.into(), main_port);
                        log::debug!("[Inbound / outgoing] peer_remote_addr={}", peer_remote_addr);
                        let mut buf = vec![0u8; 65535];
                        let handshake_len = hs.write_message(&[], &mut buf)?;
                        match gateway::send(main_sock, &buf[..handshake_len], &peer_remote_addr)
                            .await
                        {
                            Ok(_) => {
                                log::debug!("[Inbound / outgoing] Handshake scceeded and sending the packet");
                                let len = hs.write_message(raw_packet.get_bytes(), &mut buf)?;
                                match gateway::send(main_sock, &buf[..len], &peer_remote_addr).await
                                {
                                    Ok(_) => {
                                        log::debug!(
                                                    "[Inbound / outgoing] Session established: peer_private={}, peer_remote={}",
                                                    peer_private_addr, peer_remote_addr
                                                );
                                    }
                                    Err(e) => {
                                        log::warn!("[Inbound / outgoing] Could not send the packet. reason={:?}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("[Inbound / outgoing] Handshake failed. peer_private={}, reason={:?}", peer_private_addr, e);
                            }
                        }
                    }
                    // Received packet from a registered peer
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
                        match payload[0] {
                            // Afer the handshake
                            2 => {
                                let len = peer
                                    .ts
                                    .as_mut()
                                    .write_message(raw_packet.get_bytes(), &mut peer.buf)?;
                                match gateway::send(main_sock, &peer.buf[..len], &peer.remote_addr)
                                    .await
                                {
                                    Ok(_) => {
                                        log::debug!(
                                        "[Inbound / outgoing] Sent packet. peer_private={}, peer_public={}",
                                        peer_private_addr, peer.remote_addr
                                    );
                                    }
                                    Err(e) => {
                                        log::warn!(
                                        "[Inbound / outgoing] Could not send the data. peer_private={}, reason={:?}",
                                        peer_private_addr,
                                        e
                                    );
                                    }
                                }
                            }
                            _ => {
                                log::debug!(
                                    "[Inbound / outgoing] Ignore the packet. peer_private_addr={}, reason=Unknown payload type `{}`",
                                    peer_private_addr,
                                    payload[0],
                                );
                                continue;
                            }
                        }
                    }
                }
            }
            Some(Err(e)) => {
                log::warn!(
                    "[Inbound / outgoing] Could not read the UDP packet. reason={:?}",
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
