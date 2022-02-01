extern crate base64;

pub mod packet;

pub use self::packet::Packet;
use tracing as log;

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub async fn recv(sock: &UdpSocket) -> Result<(Packet<Vec<u8>>, SocketAddr)> {
    let mut msg_len_buf = [0u8; 2];
    let (_, src) = sock.peek_from(&mut msg_len_buf).await?;
    let msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);

    // +2 for msg_len buffer. +1 for validation to ensure not to exceed the expected message length.
    let mut msg_with_pad = vec![0u8; msg_len + 2 + 1];

    let rcv_len = sock.recv(&mut msg_with_pad[..]).await?;
    if msg_len + 2 != rcv_len {
        return Err(anyhow!(
            "Invalid packet: received message length doesn't match"
        ));
    } else {
        log::trace!("messge received");
    }
    // Trim the message
    let msg = msg_with_pad[2..msg_len + 2].to_vec();
    Ok((Packet::unchecked(msg), src))
}

pub async fn send(sock: &UdpSocket, buf: &[u8], to_addr: &SocketAddr) -> Result<()> {
    let msg_len = buf.len();
    let msg_len_buf = [(msg_len >> 8) as u8, (msg_len & 0xff) as u8];
    let send_len = sock.send_to(&[&msg_len_buf, buf].concat(), to_addr).await?;
    if msg_len + 2 != send_len {
        return Err(anyhow!(
            "could not send all data. actual={}, expected={}",
            send_len,
            msg_len + 2
        ));
    } else {
        log::trace!("messge sent");
    }
    Ok(())
}
