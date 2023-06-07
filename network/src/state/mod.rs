use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_yaml;
use sled;
use snow::StatelessTransportState;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing as log;

pub struct Network {
    db: sled::Db,
    local: HashMap<Ipv4Addr, Arc<StatelessTransportState>>,
}

impl Network {
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> Result<Network> {
        Ok(Network {
            db: sled::open(path)?,
            local: HashMap::new(),
        })
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ReservedNode {
    pub private_ipv4: Ipv4Addr,
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
    pub fn get(
        &self,
        private_ipv4: &Ipv4Addr,
    ) -> Result<(Option<Node>, Option<Arc<StatelessTransportState>>)> {
        Network::deserialize(&self.db.get(private_ipv4.to_string())?)
            .map(|node| (node, self.local.get(private_ipv4).map(|v| v.clone())))
    }

    pub fn reserve_node_knock(&mut self, private_ipv4: Ipv4Addr) -> Result<ReservedNode> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.subsec_nanos() as u16;
        self.reserve_node(private_ipv4, nonce)
    }

    pub fn reserve_node_handshake(&mut self, private_ipv4: Ipv4Addr, nonce: u16) -> Result<()> {
        self.reserve_node(private_ipv4, nonce)?;
        Ok(())
    }

    fn reserve_node(&mut self, private_ipv4: Ipv4Addr, nonce: u16) -> Result<ReservedNode> {
        log::debug!("[state] reserve_node: {}, nonce={}", private_ipv4, nonce);
        let node = ReservedNode {
            private_ipv4,
            nonce,
        };
        let v = serde_yaml::to_string(&node)?;
        self.db
            .insert(format!("{}-reserved", private_ipv4), v.as_bytes())?;
        // Don't need to flush the db. Flush it after confirming the node.
        Ok(node)
    }

    pub fn confirm_node(
        &mut self,
        private_ipv4: &Ipv4Addr,
        nonce: u16,
        public_addr: SocketAddr,
        public_addr_hole: SocketAddr,
        public_key: impl AsRef<[u8]>,
        ts: Arc<StatelessTransportState>,
    ) -> Result<Option<Node>> {
        let a: ReservedNode = if let Some(reserved) = self
            .db
            // Do not remove the reserved node information for reconnection.
            .get(format!("{}-reserved", private_ipv4))?
        {
            serde_yaml::from_slice(reserved.as_ref())?
        } else {
            return Err(anyhow!(
                "Invalid state: the node({}) is not reserved.",
                private_ipv4
            ));
        };
        if a.nonce != nonce {
            return Err(anyhow!("Invalid state: nonce not matched."));
        }

        let v = serde_yaml::to_string(&Node {
            public_addr,
            public_addr_hole,
            public_key: public_key.as_ref().to_vec(),
            nonce: a.nonce,
        })?;

        let old_value = self.db.insert(private_ipv4.to_string(), v.as_bytes())?;
        self.local.insert(private_ipv4.clone(), ts);
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
    pub ts: Arc<StatelessTransportState>,
    pub public_addr: SocketAddr,
    pub public_addr_hole: SocketAddr,
}
