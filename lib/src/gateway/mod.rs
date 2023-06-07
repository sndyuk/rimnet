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
    let mut total_len_buf = [0u8; 2];
    let (rcv_len, src) = sock.peek_from(&mut total_len_buf).await?;
    if rcv_len != 2 {
        // Drop the invalid message.
        sock.recv(&mut total_len_buf).await?;

        return Err(anyhow!(
            "Invalid packet: received message length doesn't match. rcv_len={}",
            rcv_len
        ));
    }
    let total_len = ((total_len_buf[0] as usize) << 8) + (total_len_buf[1] as usize);
    let mut msg = vec![0u8; total_len];
    let rcv_len = sock.recv(&mut msg).await?;
    if rcv_len != total_len {
        return Err(anyhow!(
            "Invalid packet: received message length doesn't match. expected message length={}, actual={}",
            total_len,
            rcv_len,
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
    send_raw(sock, packet.as_ref(), to_addr).await
}

pub async fn send_raw(sock: &UdpSocket, buf: impl AsRef<[u8]>, to_addr: &SocketAddr) -> Result<()> {
    let buf = buf.as_ref();
    let send_len = sock.send_to(buf, to_addr).await?;
    if send_len != buf.len() {
        return Err(anyhow!(
            "could not send all data. actual message length={}, expected={}",
            send_len,
            buf.len()
        ));
    } else {
        log::trace!("messge sent to {:?}", sock);
    }
    Ok(())
}
