extern crate base64;

use anyhow::Result;
use log::debug;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub const SEPARATOR: u8 = 0b1000_000;
pub struct RawPacket<'a> {
    pub src_ip: &'a [u8],
    pub src_port: u16,
    pub dst_ip: &'a [u8],
    pub dst_port: u16,
    pub cap: &'a [u8],
    pub data: &'a [u8],
}

pub trait RawPacketValidator {
    fn validate(&self) -> bool;
}

impl<'a> RawPacketValidator for RawPacket<'a> {
    fn validate(&self) -> bool {
        for i in 0..self.cap.len() {
            if self.cap[i] & 0b1000_0000 == 0b1000_0000 {
                debug!("capability bits must not be start with '1' for every 8 bit");
                return false;
            }
        }
        true
    }
}

impl<'a> Into<Vec<u8>> for RawPacket<'a> {
    fn into(self) -> Vec<u8> {
        debug_assert!(self.validate());
        [
            self.src_ip,
            &[(self.src_port >> 8) as u8, self.src_port as u8],
            self.dst_ip,
            &[(self.dst_port >> 8) as u8, self.dst_port as u8],
            self.cap,
            &[SEPARATOR],
            self.data,
        ]
        .concat()
    }
}

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
