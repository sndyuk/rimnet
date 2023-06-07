use anyhow::*;
use std::{fmt, net::Ipv4Addr};

pub const HEADER_FIX_LEN: usize = 9;

#[derive(Copy, Clone)]
pub struct Handshake<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> fmt::Debug for Handshake<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("rimnet::packet::Handshake")
            .field("header_len", &self.header_len())
            .field("nonce", &self.nonce())
            .field("public_ipv4", &self.public_ipv4())
            .field("public_port", &self.public_port())
            .field("public_key", &base64::encode(&self.public_key()))
            .finish()
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Handshake<B> {
    fn as_ref(&self) -> &[u8] {
        &self.buffer.as_ref()
    }
}

impl<B: AsRef<[u8]>> Handshake<B> {
    pub fn unchecked(buffer: B) -> Handshake<B> {
        Handshake { buffer }
    }

    pub fn header_len(&self) -> u8 {
        self.buffer.as_ref()[0]
    }

    pub fn nonce(&self) -> u16 {
        ((self.buffer.as_ref()[1] as u16) << 8) | (self.buffer.as_ref()[2] as u16)
    }

    pub fn public_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer.as_ref()[3],
            self.buffer.as_ref()[4],
            self.buffer.as_ref()[5],
            self.buffer.as_ref()[6],
        )
    }

    pub fn public_port(&self) -> u16 {
        ((self.buffer.as_ref()[7] as u16) << 8) | (self.buffer.as_ref()[8] as u16)
    }

    pub fn public_key(&self) -> &[u8] {
        let header_len = self.header_len() as usize;
        let len = header_len - HEADER_FIX_LEN;
        unsafe {
            let ptr = self.buffer.as_ref().as_ptr().add(HEADER_FIX_LEN);
            std::slice::from_raw_parts(ptr, len)
        }
    }
}

#[derive(Debug)]
pub struct HandshakePacketBuilder {
    nonce: u16,
    public_ipv4: Option<Ipv4Addr>,
    public_port: u16,
    public_key: Option<Vec<u8>>,
}

impl HandshakePacketBuilder {
    pub fn new() -> Result<Self> {
        Ok(HandshakePacketBuilder {
            nonce: 0,
            public_ipv4: None,
            public_port: 0,
            public_key: None,
        })
    }

    pub fn build(self) -> Result<Handshake<Vec<u8>>> {
        let public_ipv4 = self.public_ipv4.ok_or(anyhow!("public_ipv4 is rquired"))?;
        let public_key = self.public_key.ok_or(anyhow!("public_key is rquired"))?;
        let header_len = (HEADER_FIX_LEN + public_key.len()) as u8;
        Ok(Handshake::unchecked(
            [
                &[header_len] as &[u8],
                &[(self.nonce >> 8) as u8, (self.nonce & 0b11111111) as u8] as &[u8],
                &public_ipv4.octets(),
                &[
                    (self.public_port >> 8) as u8,
                    (self.public_port & 0b11111111) as u8,
                ] as &[u8],
                public_key.as_ref(),
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
    pub fn nonce(mut self, value: u16) -> Result<Self> {
        self.nonce = value;

        Ok(self)
    }

    pub fn public_ipv4(mut self, value: Ipv4Addr) -> Result<Self> {
        self.public_ipv4 = Some(value);

        Ok(self)
    }

    pub fn public_port(mut self, value: u16) -> Result<Self> {
        self.public_port = value;

        Ok(self)
    }

    pub fn public_key(mut self, value: impl AsRef<[u8]>) -> Result<Self> {
        self.public_key = Some(value.as_ref().to_vec());

        Ok(self)
    }
}
