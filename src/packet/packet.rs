extern crate base64;

use anyhow::Result;
use std::fmt;
use std::net::Ipv4Addr;

#[derive(Copy, Clone)]
pub struct Packet<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("rimnet::Packet")
            .field("version", &self.version())
            .field("header length", &self.header_len())
            .field("source", &self.source_ipv4())
            .field("source port", &self.source_port())
            .field("destination", &self.destination_ipv4())
            .field("destination port", &self.destination_port())
            .field("payload", &self.payload())
            .finish()
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Packet<B> {
    fn as_ref(&self) -> &[u8] {
        &self.buffer.as_ref()
    }
}

impl<B: AsRef<[u8]>> Packet<B> {
    /// Create an packet without checking the buffer.
    pub fn unchecked(buffer: B) -> Packet<B> {
        Packet { buffer }
    }

    /// Protocol version, should be 0.
    pub fn version(&self) -> u8 {
        self.buffer.as_ref()[0] & 0b1111
    }

    /// Length of the header.
    pub fn header_len(&self) -> u8 {
        self.buffer.as_ref()[0] >> 4
    }

    /// Source IPv4 address.
    pub fn source_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer.as_ref()[1],
            self.buffer.as_ref()[2],
            self.buffer.as_ref()[3],
            self.buffer.as_ref()[4],
        )
    }

    /// Source port.
    pub fn source_port(&self) -> u16 {
        self.buffer.as_ref()[5] as u16 + self.buffer.as_ref()[6] as u16
    }

    /// Destination IPv4 address.
    pub fn destination_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer.as_ref()[7],
            self.buffer.as_ref()[8],
            self.buffer.as_ref()[9],
            self.buffer.as_ref()[10],
        )
    }

    /// Destination port.
    pub fn destination_port(&self) -> u16 {
        self.buffer.as_ref()[11] as u16 + self.buffer.as_ref()[12] as u16
    }

    /// Capability.
    pub fn capability(&self) -> &[u8] {
        let header_len = self.header_len() as usize;
        let len = header_len - 12;
        unsafe {
            let ptr = self.buffer.as_ref().as_ptr().add(12);
            std::slice::from_raw_parts(ptr, len)
        }
    }

    /// Payload.
    pub fn payload(&self) -> &[u8] {
        let header_len = self.header_len() as usize;
        let len = self.buffer.as_ref().len() - header_len;
        unsafe {
            let ptr = self.buffer.as_ref().as_ptr().add(header_len);
            std::slice::from_raw_parts(ptr, len)
        }
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Packet<B> {
    /// Source IPv4 address.
    pub fn set_source_ipv4(&mut self, value: Ipv4Addr) -> Result<&mut Self> {
        self.buffer.as_mut()[1..5].copy_from_slice(&value.octets());

        Ok(self)
    }

    /// Source port.
    pub fn set_source_port(&mut self, value: u16) -> Result<&mut Self> {
        self.buffer.as_mut()[5..7].copy_from_slice(&[(value << 4) as u8, (value & 0b1111) as u8]);

        Ok(self)
    }

    /// Destination IPv4 address.
    pub fn set_destination_ipv4(&mut self, value: Ipv4Addr) -> Result<&mut Self> {
        self.buffer.as_mut()[16..20].copy_from_slice(&value.octets());

        Ok(self)
    }

    /// Destination port.
    pub fn set_destination_port(&mut self, value: u16) -> Result<&mut Self> {
        self.buffer.as_mut()[20..22].copy_from_slice(&[(value << 4) as u8, (value & 0b1111) as u8]);

        Ok(self)
    }

    /// Capability.
    pub fn set_capability(&mut self, value: &[u8]) -> Result<&mut Self> {
        let buf = self.buffer.as_mut();
        // Update header length.
        buf[0] = buf[0] | ((value.len() as u8) << 4);
        Ok(self)
    }
}
