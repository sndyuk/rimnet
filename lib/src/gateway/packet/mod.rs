use anyhow::{anyhow, Result};
use snow;
use std::{fmt, net::Ipv4Addr};
use tracing as log;

pub mod knock_request;
pub use knock_request::*;

pub mod knock;
pub use knock::*;

pub mod query;
pub use query::*;

pub mod handshake;
pub use handshake::*;

pub mod handshake_accept;
pub use handshake_accept::*;

pub mod tcpip;
pub use tcpip::*;

const HEADER_FIX_LEN: usize = 7;

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    // ↓ Not signed

    // Execute knock.
    KnockRequest = 0b0_0001,
    // Actual knock. It triggers handshake process.
    Knock = 0b0_0010,
    // Query an unknown peer node.
    Query = 0b0_0011,

    // ↓ Signed

    // Accept inbound connection from a source agent. The source agent can send packets to the destination agent.
    Handshake = 0b1_0001,
    HandshakeAccept = 0b1_0010,
    TcpIp = 0b1_0100,

    Unknown = 0b0_0000,
}

impl From<u8> for Protocol {
    fn from(v: u8) -> Self {
        match v {
            0b0_0001 => Protocol::KnockRequest,
            0b0_0010 => Protocol::Knock,
            0b1_0001 => Protocol::Handshake,
            0b1_0010 => Protocol::HandshakeAccept,
            0b1_0100 => Protocol::TcpIp,
            _ => Protocol::Unknown,
        }
    }
}

/*
Protocol format:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Total len           |Vers.| Protocol|               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
|                                                               |
+                            Payload                            +
|                                                             ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#[derive(Copy, Clone)]
pub struct Packet<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("rimnet::packet")
            .field("version", &self.version())
            .field("protocol", &self.protocol())
            .field("source", &self.source())
            .field("total_len", &self.total_len())
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

impl<B: AsRef<[u8]>> AsRef<[u8]> for Packet<B> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl<B: AsRef<[u8]>> Packet<B> {
    pub fn unchecked(buffer: B) -> Packet<B> {
        Packet { buffer }
    }

    pub fn total_len(&self) -> u16 {
        ((self.buffer.as_ref()[0] as u16) << 8) | (self.buffer.as_ref()[1] as u16)
    }

    pub fn version(&self) -> u8 {
        (self.buffer.as_ref()[2] >> 5) & 0b00011111
    }

    pub fn protocol(&self) -> Protocol {
        Protocol::from(self.protocol_raw())
    }
    fn protocol_raw(&self) -> u8 {
        self.buffer.as_ref()[2] & 0b00011111
    }

    pub fn source(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer.as_ref()[3],
            self.buffer.as_ref()[4],
            self.buffer.as_ref()[5],
            self.buffer.as_ref()[6],
        )
    }

    pub fn payload(&self) -> impl AsRef<[u8]> {
        unsafe {
            let ptr = self.buffer.as_ref().as_ptr().add(HEADER_FIX_LEN);
            std::slice::from_raw_parts(ptr, self.total_len() as usize - HEADER_FIX_LEN)
        }
    }

    // --- Utils

    pub fn is_valid(&self) -> bool {
        self.protocol() != Protocol::Unknown
    }

    pub fn to_knock_request(&mut self) -> Result<KnockRequest<impl AsRef<[u8]>>> {
        assert!(self.protocol() == Protocol::KnockRequest);
        let knock_request = KnockRequest::unchecked(self.payload());
        log::trace!("knock_request: {:?}", knock_request);
        Ok(knock_request)
    }

    pub fn to_knock(&mut self) -> Result<Knock<impl AsRef<[u8]>>> {
        assert!(self.protocol() == Protocol::Knock);
        let knock = Knock::unchecked(self.payload());
        log::trace!("knock: {:?}", knock);
        Ok(knock)
    }

    pub fn to_handshake(
        &mut self,
        hs: &mut snow::HandshakeState,
    ) -> Result<Handshake<impl AsRef<[u8]>>> {
        assert!(self.protocol() == Protocol::Handshake);
        let mut buf = [0u8; 127];
        let new_len = hs.read_message(self.payload().as_ref(), &mut buf)?;
        assert!(new_len <= 127);
        let handshake = Handshake::unchecked(buf[..new_len].to_vec());
        log::trace!("handshake: {:?}", handshake);
        Ok(handshake)
    }

    pub fn to_handshake_accept(
        &mut self,
        hs: &mut snow::HandshakeState,
    ) -> Result<HandshakeAccept<impl AsRef<[u8]>>> {
        assert!(self.protocol() == Protocol::HandshakeAccept);
        let mut buf = [0u8; 127];
        let new_len = hs.read_message(self.payload().as_ref(), &mut buf)?;
        assert!(new_len <= 127);
        let handshake_accept = HandshakeAccept::unchecked(buf[..new_len].to_vec());
        log::trace!("handshake_accept: {:?}", handshake_accept);
        Ok(handshake_accept)
    }

    pub fn to_tcpip(
        &mut self,
        ts: &snow::StatelessTransportState,
    ) -> Result<TcpIp<impl AsRef<[u8]>>> {
        assert!(self.protocol() == Protocol::TcpIp);
        let mut buf = [0u8; 65535];
        let new_len = ts.read_message(0, self.payload().as_ref(), &mut buf)?;
        let tcpip = TcpIp::unchecked(new_len as u16, buf[..new_len].to_vec());
        log::trace!("tcpip: {:?}", tcpip);
        Ok(tcpip)
    }
}

#[derive(Debug)]
pub struct PacketBuilder {
    version: u8,
    protocol: Protocol,
    source: Option<Ipv4Addr>,
    payload_buffer: Vec<u8>,
}

impl PacketBuilder {
    pub fn new() -> Result<Self> {
        Ok(PacketBuilder {
            version: 0,
            protocol: Protocol::Unknown,
            source: None,
            payload_buffer: Vec::new(),
        })
    }

    pub fn build(self) -> Result<Packet<Vec<u8>>> {
        let source = self.source.ok_or_else(|| anyhow!("source is rquired"))?;
        let total_len = HEADER_FIX_LEN as u16 + self.payload_buffer.len() as u16;
        let buf = [
            &[
                (total_len >> 8) as u8,
                (total_len & 0xff) as u8,
                self.version << 5 | self.protocol as u8,
            ] as &[u8],
            &source.octets(),
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

    pub fn source(mut self, value: Ipv4Addr) -> Result<Self> {
        self.source = Some(value);

        Ok(self)
    }

    pub fn add_payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
        self.payload_buffer.extend(value);

        Ok(self)
    }
}
