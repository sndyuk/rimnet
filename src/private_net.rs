use lazy_static::lazy_static;
use snow::{params::NoiseParams, TransportState};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

lazy_static! {
    pub static ref NOISE_PARAMS: NoiseParams = "Noise_N_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

pub struct PrivateNet {
    pub db: HashMap<Ipv4Addr, PrivateNode>,
}

pub struct PrivateNode {
    pub public_addr: IpAddr,
    pub public_key: Vec<u8>,
}

pub trait PrivateNetRegistry {
    fn get(&self, private_addr: &Ipv4Addr) -> Option<&PrivateNode>;
    fn put(&mut self, private_ipv4: &Ipv4Addr, public_addr: IpAddr, public_key: Vec<u8>);
}

impl PrivateNetRegistry for PrivateNet {
    fn get(&self, private_addr: &Ipv4Addr) -> Option<&PrivateNode> {
        self.db.get(private_addr)
    }
    fn put(&mut self, private_addr: &Ipv4Addr, public_addr: IpAddr, public_key: Vec<u8>) {
        self.db.insert(
            private_addr.clone(),
            PrivateNode {
                public_addr,
                public_key,
            },
        );
    }
}

pub struct Peer {
    pub ts: Box<TransportState>,
    pub remote_addr: Box<SocketAddr>,
}
