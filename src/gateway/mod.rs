extern crate base64;

pub mod builder;
pub mod packet;

pub use self::packet::Packet;
pub use self::packet::HEADER_FIX_LEN;

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub async fn recv(sock: &UdpSocket) -> Result<(Vec<u8>, SocketAddr)> {
    let mut msg_len_buf = [0u8; 2];
    let (_, src) = sock.recv_from(&mut msg_len_buf).await?;
    let msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);
    let mut msg = vec![0u8; msg_len];
    let rcv_len = sock.recv(&mut msg[..]).await?;
    if msg_len != rcv_len {
        return Err(anyhow!("received message length doesn't match"));
    }
    Ok((msg, src))
}

pub async fn send(sock: &UdpSocket, buf: &[u8], to_addr: &SocketAddr) -> Result<()> {
    let msg_len = buf.len();
    let msg_len_buf = [(msg_len >> 8) as u8, (msg_len & 0xff) as u8];
    sock.send_to(&msg_len_buf, to_addr).await?;
    let send_len = sock.send_to(buf, to_addr).await?;
    if msg_len != send_len {
        return Err(anyhow!("sent message length doesn't match"));
    }
    Ok(())
}
