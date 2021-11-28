use anyhow::Result;
use std::net::Ipv4Addr;

use crate::gateway::{Packet, HEADER_FIX_LEN};

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
    capability_len: u8,
    payload_buffer: Vec<u8>,
}

impl Build for Builder {
    fn with(buffer: Vec<u8>) -> Result<Self> {
        Ok(Builder {
            version: 0,
            header_buffer: Packet::unchecked(buffer),
            capability_len: 0,
            payload_buffer: Vec::new(),
        })
    }

    fn build(mut self) -> Result<Packet<Vec<u8>>> {
        let header_len = self.capability_len + HEADER_FIX_LEN as u8;
        self.header_buffer.set_version(self.version)?;
        self.header_buffer.set_header_len(header_len)?;
        self.header_buffer
            .set_total_len(header_len as u16 + self.payload_buffer.len() as u16)?;
        Ok(Packet::unchecked(
            [
                &self.header_buffer.as_ref()[..header_len as usize],
                self.payload_buffer.as_ref(),
            ]
            .concat(),
        ))
    }
}

impl Default for Builder {
    fn default() -> Self {
        let mut buffer = Vec::with_capacity(4096);
        unsafe { buffer.set_len(4096) };
        Builder::with(buffer).unwrap()
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
        self.capability_len = value.len() as u8;
        self.header_buffer.set_capability(value)?;
        Ok(self)
    }

    /// Add payload.
    pub fn add_payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
        self.payload_buffer.extend(value);

        Ok(self)
    }
}
