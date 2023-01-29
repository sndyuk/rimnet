extern crate base64;

pub mod packet;

pub use self::packet::Packet;
use tracing as log;

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub async fn recv(
    sock: &UdpSocket,
) -> Result<(Packet<impl AsRef<[u8]> + AsMut<[u8]>>, SocketAddr)> {
    let mut msg_len_buf = [0u8; 2];
    let (rcv_len, src) = sock.peek_from(&mut msg_len_buf).await?;
    if rcv_len != 2 {
        // Drop the invalid message.
        let mut msg = vec![0u8; rcv_len];
        sock.recv(&mut msg).await?;

        return Err(anyhow!(
            "Invalid packet: received message length doesn't match. rcv_len={}",
            rcv_len
        ));
    }
    let msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);
    let mut msg = vec![0u8; msg_len];
    let rcv_len = sock.recv(&mut msg).await?;
    if rcv_len != msg_len {
        return Err(anyhow!(
            "Invalid packet: received message length doesn't match. rcv_len={}, msg_len={}",
            rcv_len,
            msg_len
        ));
    } else {
        log::trace!("messge received");
    }
    Ok((Packet::unchecked(msg), src))
}

pub async fn send(
    sock: &UdpSocket,
    packet: &packet::Packet<impl AsRef<[u8]>>,
    to_addr: &SocketAddr,
) -> Result<()> {
    let msg_len = packet.total_len() as usize;
    let send_len = sock.send_to(packet.as_ref(), to_addr).await?;
    if send_len != msg_len {
        return Err(anyhow!(
            "could not send all data. actual={}, expected={}",
            send_len,
            msg_len
        ));
    } else {
        log::trace!("messge sent to {:?}", sock);
    }
    Ok(())
}
