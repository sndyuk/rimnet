use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub async fn recv(sock: &UdpSocket) -> Result<(Vec<u8>, SocketAddr)> {
    let mut msg_len_buf = [0u8; 2];
    let (_, src) = sock.recv_from(&mut msg_len_buf).await?;
    let msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);
    let mut msg = vec![0u8; msg_len];
    sock.recv(&mut msg[..]).await?;
    Ok((msg, src))
}

pub async fn send(sock: &UdpSocket, buf: &[u8], to_addr: &SocketAddr) -> Result<()> {
    let msg_len_buf = [(buf.len() >> 8) as u8, (buf.len() & 0xff) as u8];
    sock.send_to(&msg_len_buf, to_addr).await?;
    sock.send_to(buf, to_addr).await?;
    Ok(())
}
