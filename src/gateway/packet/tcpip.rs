use anyhow::*;
use std::{fmt, net::Ipv4Addr};

pub const HEADER_FIX_LEN: usize = 5;

#[derive(Copy, Clone)]
pub struct TcpIp<B> {
    total_len: u16,
    buffer: B,
}

impl<B: AsRef<[u8]>> fmt::Debug for TcpIp<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("rimnet::packet::TcpIp")
            .field("source_ipv4", &self.source_ipv4())
            .field(
                "capability",
                &self
                    .capability()
                    .as_ref()
                    .iter()
                    .map(|n| format!("{:02X}", n))
                    .collect::<String>(),
            )
            .field(
                "payload",
                &self
                    .payload()
                    .as_ref()
                    .iter()
                    .map(|n| format!("{:02X}", n))
                    .collect::<String>(),
            )
            .finish()
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for TcpIp<B> {
    fn as_ref(&self) -> &[u8] {
        &self.buffer.as_ref()
    }
}

impl<B: AsRef<[u8]>> TcpIp<B> {
    pub fn unchecked(total_len: u16, buffer: B) -> TcpIp<B> {
        TcpIp { total_len, buffer }
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

    pub fn capability(&self) -> impl AsRef<[u8]> {
        let header_len = self.header_len() as usize;
        unsafe {
            let ptr = self.buffer.as_ref().as_ptr().add(HEADER_FIX_LEN);
            std::slice::from_raw_parts(ptr, header_len - HEADER_FIX_LEN)
        }
    }

    pub fn payload(&self) -> impl AsRef<[u8]> {
        let header_len = self.header_len() as usize;
        let len = self.total_len as usize - header_len;
        unsafe {
            let ptr = self.buffer.as_ref().as_ptr().add(header_len);
            std::slice::from_raw_parts(ptr, len)
        }
    }
}

#[derive(Debug)]
pub struct TcpIpPacketBuilder {
    source_ipv4: Option<Ipv4Addr>,
    capability: Option<Vec<u8>>,
    payload_buffer: Vec<u8>,
}

impl TcpIpPacketBuilder {
    pub fn new() -> Result<Self> {
        Ok(TcpIpPacketBuilder {
            source_ipv4: None,
            capability: None,
            payload_buffer: Vec::new(),
        })
    }

    pub fn build(self) -> Result<TcpIp<Vec<u8>>> {
        let source_ipv4 = self.source_ipv4.ok_or(anyhow!("source_ipv4 is rquired"))?;
        let header_len = self.capability.as_ref().map(|v| v.len()).unwrap_or(0) + HEADER_FIX_LEN;
        assert!(header_len <= 127);
        Ok(TcpIp::unchecked(
            header_len as u16 + self.payload_buffer.len() as u16,
            [
                &[header_len as u8] as &[u8],
                &source_ipv4.octets(),
                self.capability
                    .as_ref()
                    .map(|v| v.as_ref())
                    .unwrap_or(&[0u8; 0]),
                self.payload_buffer.as_ref(),
            ]
            .concat(),
        ))
    }
}

impl Default for TcpIpPacketBuilder {
    fn default() -> Self {
        TcpIpPacketBuilder::new().unwrap()
    }
}

impl TcpIpPacketBuilder {
    pub fn source_ipv4(mut self, value: Ipv4Addr) -> Result<Self> {
        self.source_ipv4 = Some(value);

        Ok(self)
    }

    pub fn capability(mut self, value: Vec<u8>) -> Result<Self> {
        self.capability = Some(value);
        Ok(self)
    }

    pub fn add_payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
        self.payload_buffer.extend(value);

        Ok(self)
    }
}
