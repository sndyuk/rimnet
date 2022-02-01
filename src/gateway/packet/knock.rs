use anyhow::Result;
use std::fmt;
use std::net::Ipv4Addr;

#[derive(Copy, Clone)]
pub struct Knock<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> fmt::Debug for Knock<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("rimnet::packet::Knock")
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

impl<B: AsRef<[u8]>> AsRef<[u8]> for Knock<B> {
    fn as_ref(&self) -> &[u8] {
        &self.buffer.as_ref()
    }
}

impl<B: AsRef<[u8]>> Knock<B> {
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

impl<B: AsRef<[u8]>> From<Packet> for Knock<B> {
    fn from(v: Packet) -> Self {
        assert!(v.protocol() == Protocol::Knock);
        KnockPacketBuilder::with(v.payload()).build()
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Knock<B> {}

#[derive(Debug)]
pub struct KnockPacketBuilder {
    payload_buffer: Vec<u8>,
}

impl KnockPacketBuilder {
    pub fn with(buffer: Vec<u8>) -> Result<Self> {
        Ok(KnockPacketBuilder {
            payload_buffer: Vec::new(),
        })
    }

    pub fn build(mut self) -> Result<KnockPacketBuilder<Vec<u8>>> {
        Ok(Knock::unchecked(self.payload_buffer.as_ref()))
    }
}

impl Default for KnockPacketBuilder {
    fn default() -> Self {
        let mut buffer = Vec::with_capacity(4096);
        unsafe { buffer.set_len(4096) };
        KnockPacketBuilder::with(buffer).unwrap()
    }
}

impl KnockPacketBuilder {
    /// Add payload.
    pub fn add_payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
        self.payload_buffer.extend(value);

        Ok(self)
    }
}
