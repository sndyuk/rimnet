use anyhow::*;
use std::{fmt, net::Ipv4Addr};

pub const HEADER_FIX_LEN: usize = 15;

#[derive(Copy, Clone)]
pub struct Knock<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> fmt::Debug for Knock<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("rimnet::packet::Knock")
            .field("private_ipv4", &self.private_ipv4())
            .field("public_ipv4", &self.public_ipv4())
            .field("public_port", &self.public_port())
            .field("target_private_ipv4", &self.target_private_ipv4())
            .field("public_key", &base64::encode(&self.public_key()))
            .finish()
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Knock<B> {
    fn as_ref(&self) -> &[u8] {
        &self.buffer.as_ref()
    }
}

impl<B: AsRef<[u8]>> Knock<B> {
    pub fn unchecked(buffer: B) -> Knock<B> {
        Knock { buffer }
    }

    pub fn header_len(&self) -> u8 {
        self.buffer.as_ref()[0]
    }

    pub fn private_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer.as_ref()[1],
            self.buffer.as_ref()[2],
            self.buffer.as_ref()[3],
            self.buffer.as_ref()[4],
        )
    }

    pub fn public_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer.as_ref()[5],
            self.buffer.as_ref()[6],
            self.buffer.as_ref()[7],
            self.buffer.as_ref()[8],
        )
    }

    pub fn public_port(&self) -> u16 {
        ((self.buffer.as_ref()[9] as u16) << 8) | (self.buffer.as_ref()[10] as u16)
    }

    pub fn target_private_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer.as_ref()[11],
            self.buffer.as_ref()[12],
            self.buffer.as_ref()[13],
            self.buffer.as_ref()[14],
        )
    }

    pub fn public_key(&self) -> impl AsRef<[u8]> {
        let header_len = self.header_len() as usize;
        let len = header_len - HEADER_FIX_LEN;
        unsafe {
            let ptr = self.buffer.as_ref().as_ptr().add(HEADER_FIX_LEN);
            std::slice::from_raw_parts(ptr, len)
        }
    }
}

#[derive(Debug)]
pub struct KnockPacketBuilder {
    private_ipv4: Option<Ipv4Addr>,
    public_ipv4: Option<Ipv4Addr>,
    public_port: u16,
    public_key: Option<Vec<u8>>,
    target_private_ipv4: Option<Ipv4Addr>,
}

impl KnockPacketBuilder {
    pub fn new() -> Result<Self> {
        Ok(KnockPacketBuilder {
            private_ipv4: None,
            public_ipv4: None,
            public_port: 0,
            public_key: None,
            target_private_ipv4: None,
        })
    }

    pub fn build(self) -> Result<Knock<Vec<u8>>> {
        let private_ipv4 = self
            .private_ipv4
            .ok_or(anyhow!("private_ipv4 is rquired"))?;
        let public_ipv4 = self.public_ipv4.ok_or(anyhow!("public_ipv4 is rquired"))?;
        let public_key = self.public_key.ok_or(anyhow!("public_key is rquired"))?;
        let target_private_ipv4 = self
            .public_ipv4
            .ok_or(anyhow!("target_private_ipv4 is rquired"))?;
        let header_len = (HEADER_FIX_LEN + public_key.len()) as u8;
        Ok(Knock::unchecked(
            [
                &[header_len] as &[u8],
                &private_ipv4.octets(),
                &public_ipv4.octets(),
                &[
                    (self.public_port >> 8) as u8,
                    (self.public_port & 0b11111111) as u8,
                ] as &[u8],
                &target_private_ipv4.octets(),
                public_key.as_ref(),
            ]
            .concat(),
        ))
    }
}

impl Default for KnockPacketBuilder {
    fn default() -> Self {
        KnockPacketBuilder::new().unwrap()
    }
}

impl KnockPacketBuilder {
    pub fn private_ipv4(mut self, value: Ipv4Addr) -> Result<Self> {
        self.private_ipv4 = Some(value);

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

    pub fn target_private_ipv4(mut self, value: Ipv4Addr) -> Result<Self> {
        self.target_private_ipv4 = Some(value);

        Ok(self)
    }

    pub fn public_key(mut self, value: impl AsRef<[u8]>) -> Result<Self> {
        self.public_key = Some(value.as_ref().to_vec());

        Ok(self)
    }
}
