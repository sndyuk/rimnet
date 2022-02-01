use anyhow::{anyhow, Result};
use std::net::Ipv4Addr;

pub struct NetworkConfig {
    pub name: String,
    pub mtu: i32,
    pub private_ipv4: Ipv4Addr,
    pub public_ipv4: Ipv4Addr,
    pub public_port: u16,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub struct NetworkConfigBuilder {
    name: Option<String>,
    mtu: i32,
    private_ipv4: Option<Ipv4Addr>,
    public_ipv4: Option<Ipv4Addr>,
    public_port: u16,
    private_key: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
}

impl NetworkConfigBuilder {
    pub fn new() -> Result<NetworkConfigBuilder> {
        Ok(NetworkConfigBuilder {
            name: None,
            mtu: 1500,
            private_ipv4: None,
            public_ipv4: None,
            public_port: 7891,
            private_key: None,
            public_key: None,
        })
    }

    pub fn build(mut self) -> Result<NetworkConfig> {
        Ok(NetworkConfig {
            name: self.name.unwrap_or(String::from("rimnet")),
            mtu: self.mtu,
            private_ipv4: self
                .private_ipv4
                .unwrap_or("192.168.100.10".parse::<Ipv4Addr>()?),
            public_ipv4: self.public_ipv4.unwrap_or("0.0.0.0".parse::<Ipv4Addr>()?),
            public_port: self.public_port,
            private_key: self
                .private_key
                .ok_or_else(|| anyhow!("private_key is required"))?,
            public_key: self
                .public_key
                .ok_or_else(|| anyhow!("public_key is required"))?,
        })
    }
}

impl Default for NetworkConfigBuilder {
    fn default() -> Self {
        NetworkConfigBuilder::new().unwrap()
    }
}

impl NetworkConfigBuilder {
    pub fn name<S: Into<String>>(mut self, name: S) -> Result<Self> {
        self.name = Some(name.into());
        Ok(self)
    }

    pub fn mtu(mut self, mtu: i32) -> Result<Self> {
        self.mtu = mtu;
        Ok(self)
    }

    pub fn private_ipv4(mut self, private_ipv4: Ipv4Addr) -> Result<Self> {
        self.private_ipv4 = Some(private_ipv4);
        Ok(self)
    }

    pub fn public_ipv4(mut self, public_ipv4: Ipv4Addr) -> Result<Self> {
        self.public_ipv4 = Some(public_ipv4);
        Ok(self)
    }

    pub fn public_port(mut self, public_port: u16) -> Result<Self> {
        self.public_port = public_port;
        Ok(self)
    }

    pub fn keypair(mut self, private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Self> {
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        Ok(self)
    }
}
