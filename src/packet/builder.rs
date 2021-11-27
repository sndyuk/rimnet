use anyhow::Result;
use std::net::Ipv4Addr;

use crate::packet::packet::Packet;

pub trait Build {
    fn with(buffer: Vec<u8>) -> Result<Self>
    where
        Self: Sized;

    fn build(self) -> Result<Packet<Vec<u8>>>;
}

/// Packet builder.
#[derive(Debug)]
pub struct Builder {
    version: u8,
    header_buffer: Packet<Vec<u8>>,
    payload_buffer: Vec<u8>,
}

impl Build for Builder {
    fn with(buffer: Vec<u8>) -> Result<Self> {
        Ok(Builder {
            version: 1,
            header_buffer: Packet::unchecked(buffer),
            payload_buffer: Vec::new(),
        })
    }

    fn build(self) -> Result<Packet<Vec<u8>>> {
        let header = self.header_buffer.as_ref();
        Ok(Packet::unchecked(
            [header, self.payload_buffer.as_ref()].concat(),
        ))
    }
}

impl Default for Builder {
    fn default() -> Self {
        Builder::with(Vec::new()).unwrap()
    }
}

impl Builder {
    /// Source IPv4.
    pub fn source_ipv4(mut self, value: Ipv4Addr) -> Result<Self> {
        self.header_buffer.set_source_ipv4(value)?;
        Ok(self)
    }

    /// Source port.
    pub fn source_port(mut self, value: u16) -> Result<Self> {
        self.header_buffer.set_source_port(value)?;
        Ok(self)
    }

    /// Destination IPv4.
    pub fn destination_ipv4(mut self, value: Ipv4Addr) -> Result<Self> {
        self.header_buffer.set_destination_ipv4(value)?;
        Ok(self)
    }

    /// Destination port.
    pub fn destination_port(mut self, value: u16) -> Result<Self> {
        self.header_buffer.set_destination_port(value)?;
        Ok(self)
    }

    /// Capability.
    pub fn capability(mut self, value: &[u8]) -> Result<Self> {
        self.header_buffer.set_capability(value)?;
        Ok(self)
    }

    /// Add payload.
    pub fn add_payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
        self.payload_buffer.extend(value);

        Ok(self)
    }
}
