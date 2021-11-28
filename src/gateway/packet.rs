extern crate base64;

use anyhow::Result;
use std::fmt;
use std::net::Ipv4Addr;

pub const HEADER_FIX_LEN: usize = 16;

#[derive(Copy, Clone)]
pub struct Packet<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("rimnet::Packet")
            .field("version", &self.version())
            .field("header length", &self.header_len())
            .field("total length", &self.total_len())
            .field("source", &self.source_ipv4())
            .field("source port", &self.source_port())
            .field("destination", &self.destination_ipv4())
            .field("destination port", &self.destination_port())
            .field("capability", &self.capability())
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

    /// Protocol version.
    pub fn version(&self) -> u8 {
        (self.buffer.as_ref()[0] & 0b11100000) >> 5 // Last 5 bits are reserved
    }

    /// Length of the header.
    pub fn header_len(&self) -> u8 {
        self.buffer.as_ref()[1]
    }

    /// Length of the header + payload.
    pub fn total_len(&self) -> u16 {
        ((self.buffer.as_ref()[2] as u16) << 8) + self.buffer.as_ref()[3] as u16
    }

    /// Source IPv4 address.
    pub fn source_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer.as_ref()[4],
            self.buffer.as_ref()[5],
            self.buffer.as_ref()[6],
            self.buffer.as_ref()[7],
        )
    }

    /// Source port.
    pub fn source_port(&self) -> u16 {
        ((self.buffer.as_ref()[8] as u16) << 8) + self.buffer.as_ref()[9] as u16
    }

    /// Destination IPv4 address.
    pub fn destination_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer.as_ref()[10],
            self.buffer.as_ref()[11],
            self.buffer.as_ref()[12],
            self.buffer.as_ref()[13],
        )
    }

    /// Destination port.
    pub fn destination_port(&self) -> u16 {
        ((self.buffer.as_ref()[14] as u16) << 8) + self.buffer.as_ref()[15] as u16
    }

    /// Capability.
    pub fn capability(&self) -> &[u8] {
        let header_len = self.header_len() as usize;
        let len = header_len - HEADER_FIX_LEN;
        unsafe {
            let ptr = self.buffer.as_ref().as_ptr().add(HEADER_FIX_LEN);
            std::slice::from_raw_parts(ptr, len)
        }
    }

    /// Payload.
    pub fn payload(&self) -> &[u8] {
        let header_len = self.header_len() as usize;
        let len = self.total_len() as usize - header_len;
        unsafe {
            let ptr = self.buffer.as_ref().as_ptr().add(header_len);
            std::slice::from_raw_parts(ptr, len)
        }
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Packet<B> {
    /// Version
    pub fn set_version(&mut self, value: u8) -> Result<&mut Self> {
        assert!(value <= 6);
        self.buffer.as_mut()[0] = value << 5;

        Ok(self)
    }

    /// Header length
    pub fn set_header_len(&mut self, value: u8) -> Result<&mut Self> {
        self.buffer.as_mut()[1] = value;

        Ok(self)
    }

    /// Total length
    pub fn set_total_len(&mut self, value: u16) -> Result<&mut Self> {
        self.buffer.as_mut()[2] = (value >> 8) as u8;
        self.buffer.as_mut()[3] = (value & 0b11111111) as u8;

        Ok(self)
    }

    /// Source IPv4 address.
    pub fn set_source_ipv4(&mut self, value: Ipv4Addr) -> Result<&mut Self> {
        self.buffer.as_mut()[4..8].copy_from_slice(&value.octets());

        Ok(self)
    }

    /// Source port.
    pub fn set_source_port(&mut self, value: u16) -> Result<&mut Self> {
        self.buffer.as_mut()[8] = (value >> 8) as u8;
        self.buffer.as_mut()[9] = (value & 0b11111111) as u8;

        Ok(self)
    }

    /// Destination IPv4 address.
    pub fn set_destination_ipv4(&mut self, value: Ipv4Addr) -> Result<&mut Self> {
        self.buffer.as_mut()[10..14].copy_from_slice(&value.octets());

        Ok(self)
    }

    /// Destination port.
    pub fn set_destination_port(&mut self, value: u16) -> Result<&mut Self> {
        self.buffer.as_mut()[14] = (value >> 8) as u8;
        self.buffer.as_mut()[15] = (value & 0b11111111) as u8;

        Ok(self)
    }

    /// Capability.
    pub fn set_capability(&mut self, value: &[u8]) -> Result<&mut Self> {
        let buf = self.buffer.as_mut();
        buf[HEADER_FIX_LEN..HEADER_FIX_LEN + value.len()].copy_from_slice(value);

        Ok(self)
    }
}
