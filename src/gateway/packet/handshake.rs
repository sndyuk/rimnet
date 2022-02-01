use crate::gateway::packet::Protocol;

use super::Packet;
use anyhow::*;
use snow::HandshakeState;
use std::{fmt, net::Ipv4Addr};

pub const HEADER_FIX_LEN: usize = 5;

#[derive(Copy, Clone)]
pub struct Handshake<B> {
    total_len: u16,
    buffer: B,
}

impl<B: AsRef<[u8]>> fmt::Debug for Handshake<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("rimnet::packet::Handshake")
            .field(
                "payload",
                &self
                    .payload()
                    .iter()
                    .map(|n| format!("{:02X}", n))
                    .collect::<String>(),
            )
            .finish()
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Handshake<B> {
    fn as_ref(&self) -> &[u8] {
        &self.buffer.as_ref()
    }
}

impl<B: AsRef<[u8]>> Handshake<B> {
    pub fn unchecked(total_len: u16, buffer: B) -> Handshake<B> {
        Handshake { total_len, buffer }
    }

    pub fn header_len(&self) -> u8 {
        self.buffer.as_ref()[0]
    }

    pub fn source_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer.as_ref()[1],
            self.buffer.as_ref()[2],
            self.buffer.as_ref()[3],
            self.buffer.as_ref()[4],
        )
    }

    pub fn public_key(&self) -> &[u8] {
        let header_len = self.header_len() as usize;
        let len = header_len - HEADER_FIX_LEN;
        unsafe {
            let ptr = self.buffer.as_ref().as_ptr().add(HEADER_FIX_LEN);
            std::slice::from_raw_parts(ptr, len)
        }
    }

    pub fn payload(&self) -> &[u8] {
        let header_len = self.header_len() as usize;
        let len = self.total_len as usize - header_len;
        unsafe {
            let ptr = self.buffer.as_ref().as_ptr().add(header_len);
            std::slice::from_raw_parts(ptr, len)
        }
    }
}

#[derive(Debug)]
pub struct HandshakePacketBuilder {
    source_ipv4: Option<Ipv4Addr>,
    public_key: Option<Vec<u8>>,
    payload_buffer: Vec<u8>,
}

impl HandshakePacketBuilder {
    pub fn new() -> Result<Self> {
        Ok(HandshakePacketBuilder {
            public_key: None,
            source_ipv4: None,
            payload_buffer: Vec::new(),
        })
    }

    pub fn build(self) -> Result<Handshake<Vec<u8>>> {
        let source_ipv4 = self.source_ipv4.ok_or(anyhow!("source_ipv4 is rquired"))?;
        let public_key = self.public_key.ok_or(anyhow!("public_key is rquired"))?;
        let header_len = (4 + public_key.len()) as u8;
        Ok(Handshake::unchecked(
            header_len as u16 + self.payload_buffer.len() as u16,
            [
                &[header_len] as &[u8],
                &source_ipv4.octets(),
                public_key.as_ref(),
                self.payload_buffer.as_ref(),
            ]
            .concat(),
        ))
    }
}

impl Default for HandshakePacketBuilder {
    fn default() -> Self {
        HandshakePacketBuilder::new().unwrap()
    }
}

impl HandshakePacketBuilder {
    pub fn source_ipv4(mut self, value: Ipv4Addr) -> Result<Self> {
        self.source_ipv4 = Some(value);

        Ok(self)
    }

    pub fn public_key(mut self, value: Vec<u8>) -> Result<Self> {
        self.public_key = Some(value);

        Ok(self)
    }

    pub fn add_payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
        self.payload_buffer.extend(value);

        Ok(self)
    }
}
