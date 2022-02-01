use anyhow::Result;
use snow::{HandshakeState, TransportState};
use std::fmt;

pub mod handshake;
pub use handshake::*;

pub mod tcpip;
pub use tcpip::*;

const HEADER_FIX_LEN: usize = 3;

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    // ↓ Not encrypted
    Knock = 0b0_0001,
    // ↓ Encrypted
    Handshake = 0b1_0001,
    TcpIp = 0b1_0010,

    Unknown = 0b0_0000,
}

impl From<u8> for Protocol {
    fn from(v: u8) -> Self {
        match v {
            0b0_0001 => Protocol::Knock,
            0b1_0001 => Protocol::Handshake,
            0b1_0010 => Protocol::TcpIp,
            _ => Protocol::Unknown,
        }
    }
}

#[derive(Copy, Clone)]
pub struct Packet<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("rimnet::packet")
            .field("version", &self.version())
            .field("protocol", &self.protocol())
            .field("total_len", &self.total_len())
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
    pub fn unchecked(buffer: B) -> Packet<B> {
        Packet { buffer }
    }

    pub fn version(&self) -> u8 {
        (self.buffer.as_ref()[0] >> 5) & 0b00011111
    }

    pub fn protocol(&self) -> Protocol {
        Protocol::from(self.protocol_raw())
    }
    fn protocol_raw(&self) -> u8 {
        self.buffer.as_ref()[0] & 0b00011111
    }

    pub fn total_len(&self) -> u16 {
        ((self.buffer.as_ref()[1] as u16) << 8) | (self.buffer.as_ref()[2] as u16)
    }

    pub fn payload(&self) -> &[u8] {
        let len = self.total_len() as usize - HEADER_FIX_LEN;
        unsafe {
            let ptr = self.buffer.as_ref().as_ptr().add(HEADER_FIX_LEN);
            std::slice::from_raw_parts(ptr, len)
        }
    }

    // --- Utils

    /// Is valid
    pub fn is_valid(&self) -> bool {
        self.protocol() != Protocol::Unknown
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Packet<B> {
    pub fn set_version(&mut self, value: u8) -> Result<&mut Self> {
        assert!(value <= 6);
        self.buffer.as_mut()[0] = value << 5 | self.protocol_raw();

        Ok(self)
    }

    pub fn set_protocol(&mut self, value: Protocol) -> Result<&mut Self> {
        self.buffer.as_mut()[0] = self.version() | (value as u8 & 0b00011111);

        Ok(self)
    }

    pub fn set_total_len(&mut self, value: u16) -> Result<&mut Self> {
        self.buffer.as_mut()[1] = (value >> 8) as u8;
        self.buffer.as_mut()[2] = (value & 0b11111111) as u8;

        Ok(self)
    }

    pub fn set_capability(&mut self, value: &[u8]) -> Result<&mut Self> {
        let buf = self.buffer.as_mut();
        buf[HEADER_FIX_LEN..HEADER_FIX_LEN + value.len()].copy_from_slice(value);

        Ok(self)
    }

    // --- Utils

    pub fn to_handshake(&mut self, hs: &mut HandshakeState) -> Result<Handshake<Vec<u8>>> {
        assert!(self.protocol() == Protocol::Handshake);
        let mut buf = [0u8; 64];
        let new_len = hs.read_message(self.payload(), &mut buf)?;
        let handshake = Handshake::unchecked(new_len as u16, buf[..new_len].to_vec());
        Ok(handshake)
    }

    pub fn to_tcpip(&mut self, ts: &mut TransportState) -> Result<TcpIp<Vec<u8>>> {
        assert!(self.protocol() == Protocol::TcpIp);
        let mut buf = [0u8; 65535];
        let new_len = ts.read_message(self.payload(), &mut buf)?;
        let tcpip = TcpIp::unchecked(new_len as u16, buf[..new_len].to_vec());
        Ok(tcpip)
    }
}

#[derive(Debug)]
pub struct PacketBuilder {
    version: u8,
    protocol: Protocol,
    payload_buffer: Vec<u8>,
}

impl PacketBuilder {
    pub fn new() -> Result<Self> {
        Ok(PacketBuilder {
            version: 0,
            protocol: Protocol::Unknown,
            payload_buffer: Vec::new(),
        })
    }

    pub fn build(self) -> Result<Packet<Vec<u8>>> {
        let total_len = HEADER_FIX_LEN as u16 + self.payload_buffer.len() as u16;
        let buf = [
            &[
                self.version << 5 | self.protocol as u8,
                (total_len >> 8) as u8,
                (total_len & 0b11111111) as u8,
            ] as &[u8],
            self.payload_buffer.as_ref(),
        ]
        .concat();
        Ok(Packet::unchecked(buf))
    }
}

impl Default for PacketBuilder {
    fn default() -> Self {
        PacketBuilder::new().unwrap()
    }
}

impl PacketBuilder {
    pub fn version(mut self, value: u8) -> Result<Self> {
        self.version = value;

        Ok(self)
    }

    pub fn protocol(mut self, value: Protocol) -> Result<Self> {
        self.protocol = value;

        Ok(self)
    }

    pub fn add_payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
        self.payload_buffer.extend(value);

        Ok(self)
    }
}