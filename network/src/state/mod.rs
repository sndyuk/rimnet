use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_yaml;
use sled;
use snow::TransportState;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing as log;

pub struct Network {
    db: sled::Db,
}

impl Network {
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> Result<Network> {
        Ok(Network {
            db: sled::open(path)?,
        })
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ReservedNode {
    pub public_addr: SocketAddr,
    pub nonce: u16,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Node {
    pub public_addr: SocketAddr,
    pub public_addr_hole: SocketAddr,
    pub public_key: Vec<u8>,
    pub nonce: u16,
}

impl Network {
    pub fn get(&self, private_addr: &Ipv4Addr) -> Result<Option<Node>> {
        Network::deserialize(&self.db.get(private_addr.to_string())?)
    }

    pub fn reserve_node(&mut self, public_addr: SocketAddr) -> Result<ReservedNode> {
        log::debug!("[state] reserve_node: {}", public_addr);
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.subsec_nanos() as u16;
        let node = ReservedNode { public_addr, nonce };
        let v = serde_yaml::to_string(&node)?;
        self.db.insert(
            format!("{}-reserved", public_addr.to_string()),
            v.as_bytes(),
        )?;
        // Don't need to flush the db. Flush it after confirming the node.
        Ok(node)
    }

    pub fn confirm_node(
        &mut self,
        private_addr: &Ipv4Addr,
        nonce: u16,
        public_addr: SocketAddr,
        public_addr_hole: SocketAddr,
        public_key: impl AsRef<[u8]>,
    ) -> Result<Option<Node>> {
        let a: ReservedNode = if let Some(reserved) = self
            .db
            // Do not remove the reserved node information for reconnection.
            .get(format!("{}-reserved", public_addr.to_string()))?
        {
            serde_yaml::from_slice(reserved.as_ref())?
        } else {
            return Err(anyhow!(format!(
                "Invalid state: the node({}) is not reserved.",
                public_addr
            )));
        };
        if a.nonce != nonce {
            return Err(anyhow!(format!("Invalid state: nonce not matched.")));
        }

        let v = serde_yaml::to_string(&Node {
            public_addr,
            public_addr_hole,
            public_key: public_key.as_ref().to_vec(),
            nonce: a.nonce,
        })?;

        let old_value = self.db.insert(private_addr.to_string(), v.as_bytes())?;
        self.db.flush()?;

        Network::deserialize(&old_value)
    }

    fn deserialize<'de, T: Deserialize<'de>>(value: &'de Option<sled::IVec>) -> Result<Option<T>> {
        if let Some(v) = value {
            Ok(Some(serde_yaml::from_slice::<T>(v.as_ref())?))
        } else {
            Ok(None)
        }
    }
}

pub struct Peer {
    pub ts: Box<TransportState>,
    pub public_addr: SocketAddr,
    pub public_addr_hole: SocketAddr,
}
