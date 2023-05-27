use anyhow::*;
use std::{fmt, net::Ipv4Addr};

#[derive(Copy, Clone)]
pub struct KnockRequest<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> fmt::Debug for KnockRequest<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("rimnet::packet::KnockRequest")
            .field("public_ipv4", &self.public_ipv4())
            .field("public_port", &self.public_port())
            .finish()
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for KnockRequest<B> {
    fn as_ref(&self) -> &[u8] {
        &self.buffer.as_ref()
    }
}

impl<B: AsRef<[u8]>> KnockRequest<B> {
    pub fn unchecked(buffer: B) -> KnockRequest<B> {
        KnockRequest { buffer }
    }

    pub fn public_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer.as_ref()[0],
            self.buffer.as_ref()[1],
            self.buffer.as_ref()[2],
            self.buffer.as_ref()[3],
        )
    }

    pub fn public_port(&self) -> u16 {
        ((self.buffer.as_ref()[4] as u16) << 8) | (self.buffer.as_ref()[5] as u16)
    }
}

#[derive(Debug)]
pub struct KnockRequestPacketBuilder {
    public_ipv4: Option<Ipv4Addr>,
    public_port: u16,
}

impl KnockRequestPacketBuilder {
    pub fn new() -> Result<Self> {
        Ok(KnockRequestPacketBuilder {
            public_ipv4: None,
            public_port: 0,
        })
    }

    pub fn build(self) -> Result<KnockRequest<Vec<u8>>> {
        let public_ipv4 = self.public_ipv4.ok_or(anyhow!("public_ipv4 is rquired"))?;
        Ok(KnockRequest::unchecked(
            [
                &public_ipv4.octets(),
                &[
                    (self.public_port >> 8) as u8,
                    (self.public_port & 0b11111111) as u8,
                ] as &[u8],
            ]
            .concat(),
        ))
    }
}

impl Default for KnockRequestPacketBuilder {
    fn default() -> Self {
        KnockRequestPacketBuilder::new().unwrap()
    }
}

impl KnockRequestPacketBuilder {
    pub fn public_ipv4(mut self, value: Ipv4Addr) -> Result<Self> {
        self.public_ipv4 = Some(value);

        Ok(self)
    }

    pub fn public_port(mut self, value: u16) -> Result<Self> {
        self.public_port = value;

        Ok(self)
    }
}
