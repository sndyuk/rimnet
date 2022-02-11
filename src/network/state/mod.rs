use anyhow::Result;
use snow::TransportState;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

pub struct Network {
    db: HashMap<Ipv4Addr, Node>,
}

impl Network {
    pub fn new() -> Result<Network> {
        Ok(Network { db: HashMap::new() })
    }
}

pub struct Node {
    pub public_addr: IpAddr,
    pub public_key: Vec<u8>,
}

impl Network {
    pub fn get(&self, private_addr: &Ipv4Addr) -> Option<&Node> {
        self.db.get(private_addr)
    }
    pub fn put(
        &mut self,
        private_addr: &Ipv4Addr,
        public_addr: IpAddr,
        public_key: impl AsRef<[u8]>,
    ) {
        self.db.insert(
            private_addr.clone(),
            Node {
                public_addr,
                public_key: public_key.as_ref().to_vec(),
            },
        );
    }
}

pub struct Peer {
    pub ts: Box<TransportState>,
    pub remote_addr: Box<SocketAddr>,
}
