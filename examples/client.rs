extern crate base64;
extern crate tun;

use lazy_static::lazy_static;

use anyhow::{Context, Result};
use clap::Parser;
use snow::{params::NoiseParams, Builder};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

use rimnet::message::{self, RawPacket};

lazy_static! {
    static ref PARAMS: NoiseParams = "Noise_N_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

#[derive(Parser)]
#[clap()]
struct Opts {
    #[clap(short, long)]
    key: String,
    #[clap(short, long, default_value = "7891")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts: Opts = Opts::parse();
    let remote_public_key = opts.key;
    let port = opts.port;
    println!("public key: {:?}", remote_public_key);
    send_sample_messages(&base64::decode(remote_public_key)?, port)
        .await
        .context("Failed to run a client")?;
    println!("all done.");
    Ok(())
}

async fn send_sample_messages(remote_public_key: &Vec<u8>, port: u16) -> Result<()> {
    let mut buf = vec![0u8; 65535];

    let builder: Builder<'_> = Builder::new(PARAMS.clone());
    let local_keypair = builder.generate_keypair()?;
    let mut noise = builder
        .local_private_key(&local_keypair.private)
        .remote_public_key(remote_public_key)
        .build_initiator()?;

    // Connect to the remote client
    let mut sock = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = format!("127.0.0.1:{}", port).parse::<SocketAddr>()?;
    println!("connected...");

    // Start handshake
    let handshake_len = noise.write_message(&[], &mut buf)?;
    message::send(&mut sock, &buf[..handshake_len], &server_addr).await?;

    let mut noise = noise.into_transport_mode()?;
    println!("session established...");

    // Send data
    let cap: [u8; 8] = [
        0b0000_0010,
        0b0000_0010,
        0b0000_0100,
        0b0000_0100,
        0b0000_1000,
        0b0000_1000,
        0b0000_1111,
        0b0000_0111,
    ];
    for _ in 0..10 {
        let packet: Vec<u8> = RawPacket {
            src_ip: &[10, 0, 0, 2],
            src_port: 8080,
            dst_ip: &[10, 0, 0, 3],
            dst_port: 8080,
            cap: &cap,
            data: b"TEST DATA!",
        }
        .into();
        let len = noise.write_message(&packet[..], &mut buf)?;
        message::send(&mut sock, &buf[..len], &server_addr).await?;
    }
    println!("notified server of intent to hack planet.");
    Ok(())
}
