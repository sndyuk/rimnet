use anyhow::*;
pub mod config;
pub use config::*;
use snow::Builder as SnowBuilder;
mod device;
mod inbound;
mod state;

pub async fn run(config: NetworkConfig) -> Result<()> {
    inbound::run(config).await?;
    Ok(())
}

pub struct Keypair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}
pub fn generate_keypair() -> Result<Keypair> {
    let snow_keypair = SnowBuilder::new(inbound::NOISE_PARAMS.clone()).generate_keypair()?;
    Ok(Keypair {
        private: snow_keypair.private,
        public: snow_keypair.public,
    })
}
