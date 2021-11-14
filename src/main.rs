extern crate base64;

use clap::Parser;

use anyhow::Result;
use env_logger::{self, Env};
use log::{debug, error, info, warn};
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::{collections::HashMap, net::SocketAddr};
use tokio::sync::Mutex;
use tun::{AsyncDevice, TunPacketCodec};

use lazy_static::lazy_static;
use snow::{params::NoiseParams, Builder, TransportState};

use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::UdpSocket;

use futures::StreamExt;
use packet::{ip::v4, Packet};
use tokio_util::codec::FramedRead;

mod inbound;
mod message;

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

    // Start TUN
    let tun = inbound::run_tun(&opts.tun_device_name, opts.mtu).await?;
    let (reader, mut writer) = tokio::io::split(tun);
    let codec = TunPacketCodec::new(true, opts.mtu);
    let mut frame_reader = FramedRead::new(reader, codec);

    // Listen the main traffic port
    let main_sock_addr = Arc::new(UdpSocket::bind(format!("127.0.0.1:{}", opts.port)).await?);
    info!("listening on {:?}", main_sock_addr.local_addr().unwrap());

    // Prepare keypair for Noise
    let keypair = Builder::new(PARAMS.clone()).generate_keypair()?;
    info!("public key: {:?}", base64::encode(&keypair.public));

    // Prepare public keys
    let public_keys = Arc::new(Mutex::new(PrivateNet { db: HashMap::new() }));

    // Inbound outging loop
    let inbound_outgoing_loop = tokio::spawn({
        let main_sock_addr = main_sock_addr.clone();
        let private_key = keypair.private.clone();
        let public_keys = public_keys.clone();
        async move {
            match listen_inbound_outgoing(
                &mut frame_reader,
                &main_sock_addr,
                opts.port,
                public_keys,
                private_key,
            )
            .await
            {
                Ok(_) => true,
                Err(e) => {
                    log::error!("[Inbound / outgoing] {:?}", e);
                    false
                }
            }
        }
    });
    debug!("[Inbound / outgoing] Main loop started");

    // Writer loop
    let inbound_incomming_loop = tokio::spawn({
        let main_sock_addr = main_sock_addr.clone();
        let private_key = keypair.private.clone();
        async move {
            match listen_inbound_incomming(&mut writer, &main_sock_addr, public_keys, private_key)
                .await
            {
                Ok(_) => true,
                Err(e) => {
                    log::error!("[Inbound / incomming] {:?}", e);
                    false
                }
            }
        }
    });
    debug!("[Inbound / incomming] Main loop started");

    inbound_outgoing_loop.await?;
    inbound_incomming_loop.await?;
    Ok(())
}

struct PrivateNet {
    db: HashMap<Ipv4Addr, PrivateNode>,
}

struct PrivateNode {
    public_ipv4: Ipv4Addr,
    public_key: Vec<u8>,
}

trait PrivateNetRegistry {
    fn get(&self, private_addr: &Ipv4Addr) -> Option<&PrivateNode>;
    fn put(&mut self, private_addr: &Ipv4Addr, public_ipv4: &Ipv4Addr, public_key: Vec<u8>);
}

impl PrivateNetRegistry for PrivateNet {
    fn get(&self, private_addr: &Ipv4Addr) -> Option<&PrivateNode> {
        self.db.get(private_addr)
    }
    fn put(&mut self, private_addr: &Ipv4Addr, public_ipv4: &Ipv4Addr, public_key: Vec<u8>) {
        self.db.insert(
            private_addr.clone(),
            PrivateNode {
                public_ipv4: public_ipv4.clone(),
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
                let packet = v4::Packet::unchecked(raw_packet.get_bytes());
                let peer_private_addr = packet.source();
                let private_net = private_net.lock().await;
                match peers.get_mut(&peer_private_addr) {
                    // Received packet from a unknown peer
                    None => {
                        let remote_node = match private_net.get(&peer_private_addr) {
                            Some(remote_public_key) => remote_public_key,
                            None => {
                                warn!("[Inbound / outgoing] The client doesn't registered. peer_private_addr={}", peer_private_addr);
                                continue;
                            }
                        };
                        let mut hs = Builder::new(PARAMS.clone())
                            .local_private_key(&private_key)
                            .remote_public_key(&remote_node.public_key)
                            .build_responder()?;

                        debug!("[Inbound / outgoing] Start handshake");
                        let peer_remote_addr = SocketAddr::new(peer_private_addr.into(), main_port);
                        debug!("[Inbound / outgoing] peer_remote_addr={}", peer_remote_addr);
                        let mut buf = vec![0u8; 65535];
                        let handshake_len = hs.write_message(&[], &mut buf)?;
                        match message::send(main_sock, &buf[..handshake_len], &peer_remote_addr)
                            .await
                        {
                            Ok(_) => {
                                debug!("[Inbound / outgoing] Handshake scceeded and sending the packet");
                                let len = hs.write_message(raw_packet.get_bytes(), &mut buf)?;
                                match message::send(main_sock, &buf[..len], &peer_remote_addr).await
                                {
                                    Ok(_) => {
                                        debug!(
                                                    "[Inbound / outgoing] Session established: peer_private={}, peer_remote={}",
                                                    peer_private_addr, peer_remote_addr
                                                );
                                    }
                                    Err(e) => {
                                        warn!("[Inbound / outgoing] Could not send the packet. reason={:?}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("[Inbound / outgoing] Handshake failed. peer_private={}, reason={:?}", peer_private_addr, e);
                            }
                        }
                    }
                    // Received packet from a registered peer
                    Some(peer) => {
                        debug!("[Inbound / outgoing] Sending the packet");
                        let payload = packet.payload();
                        if payload.len() == 0 {
                            debug!(
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
                                match message::send(main_sock, &peer.buf[..len], &peer.remote_addr)
                                    .await
                                {
                                    Ok(_) => {
                                        debug!(
                                        "[Inbound / outgoing] Sent packet. peer_private={}, peer_public={}",
                                        peer_private_addr, peer.remote_addr
                                    );
                                    }
                                    Err(e) => {
                                        warn!(
                                        "[Inbound / outgoing] Could not send the data. peer_private={}, reason={:?}",
                                        peer_private_addr,
                                        e
                                    );
                                    }
                                }
                            }
                            _ => {
                                debug!(
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
                warn!(
                    "[Inbound / outgoing] Could not read the UDP packet. reason={:?}",
                    e
                );
                continue;
            }
            None => {
                warn!("[Inbound / outgoing] Could not read the UDP packet. reason=unknown");
                continue;
            }
        }
    }
}

async fn listen_inbound_incomming(
    tun_writer: &mut WriteHalf<AsyncDevice>,
    main_sock: &UdpSocket,
    private_net: Arc<Mutex<PrivateNet>>,
    private_key: Vec<u8>,
) -> Result<()> {
    let mut peers: HashMap<Ipv4Addr, Peer> = HashMap::new();

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
        match message::recv(main_sock).await {
            Ok((raw_packet, peer_remote_addr)) => {
                let packet = v4::Packet::unchecked(raw_packet);
                let peer_private_addr = packet.source();
                match peers.get_mut(&peer_private_addr) {
                    // Before the handshake. The first packet must be the handshake request.
                    None => {
                        debug!("[Inbound / incomming] Start handshake");

                        let peer_public_key = match private_net.lock().await.get(&peer_private_addr)
                        {
                            Some(node) => node.public_key.clone(),
                            None => {
                                log::warn!(
                                    "The node is not regstered. private_ipv4={}",
                                    peer_private_addr
                                );
                                continue;
                            }
                        };

                        let mut hs = Builder::new(PARAMS.clone())
                            .local_private_key(&private_key)
                            .remote_public_key(&peer_public_key)
                            .build_responder()?;

                        let mut buf = vec![0u8; 65535];
                        match hs.read_message(packet.payload(), &mut buf) {
                            Ok(_) => {
                                debug!("[Inbound / incomming] Handshake scceeded");
                                peers.insert(
                                    peer_private_addr,
                                    Peer {
                                        ts: Box::new(hs.into_transport_mode()?),
                                        buf,
                                        remote_addr: Box::new(peer_remote_addr),
                                    },
                                );
                                debug!(
                                    "[Inbound / incomming] Session established: peer_private={}, peer_remote={}",
                                    peer_private_addr, peer_remote_addr
                                );
                            }
                            Err(e) => {
                                warn!("[Inbound / incomming] Handshake failed. peer_private={}, reason={:?}", peer_private_addr, e);
                            }
                        };
                    }
                    // Afer the handshake
                    Some(peer) => {
                        debug!("[Inbound / incomming] Decrypting the payload");
                        match peer
                            .ts
                            .as_mut()
                            .read_message(packet.payload(), &mut peer.buf)
                        {
                            Ok(len) => {
                                debug!("[Inbound / incomming] Message decrypted. len={}", len);

                                /*
                                let src_ip = Ipv4Addr::new(
                                    peer.buf[0],
                                    peer.buf[1],
                                    peer.buf[2],
                                    peer.buf[3],
                                );
                                let src_port = LittleEndian::read_u16(&[peer.buf[4], peer.buf[5]]);
                                let dst_ip = Ipv4Addr::new(
                                    peer.buf[6],
                                    peer.buf[7],
                                    peer.buf[8],
                                    peer.buf[9],
                                );
                                let dst_port =
                                    LittleEndian::read_u16(&[peer.buf[10], peer.buf[11]]);
                                let mut cap_pos = 0;
                                for i in 12..len {
                                    if peer.buf[i] == message::SEPARATOR {
                                        cap_pos = i;
                                        break;
                                    }
                                }
                                let data = &peer.buf[cap_pos + 1..len];
                                debug!("src ip: {}, dst ip: {}", src_ip, dst_ip);
                                debug!("peer said: {}", String::from_utf8_lossy(data));
                                */

                                tun_writer.write_all(&peer.buf).await?;
                            }
                            Err(e) => {
                                error!(
                                    "[Inbound / incomming] Could not decrypt the payload. peer_private={}. reason={:?}",
                                    peer_private_addr, e
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Could not read the UDP packet. {:?}", e);
                continue;
            }
        }
    }
}
