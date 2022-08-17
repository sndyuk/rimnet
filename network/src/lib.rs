use anyhow::*;
pub mod config;
pub use config::*;
use snow::Builder as SnowBuilder;
mod device;
mod inbound;
mod state;
use regex::Regex;
use std::fs;

pub async fn run(config: NetworkConfig) -> Result<()> {
    inbound::run(config).await?;
    Ok(())
}

pub struct Keypair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

impl Keypair {
    pub fn save_to_file(&self, name: &str) -> Result<()> {
        let re = Regex::new(r"^[a-zA-Z][0-9a-zA-Z\.]{2,22}$").unwrap();
        if !re.is_match(name) {
            return Err(anyhow!(
                "name must be alphanumerics and dots and smaller than 24 characters"
            ));
        }

        let public_key = base64::encode(&self.public);
        let private_key = base64::encode(&self.private);
        fs::write(format!("{}.pub", name), public_key)?;
        fs::write(format!("{}", name), private_key)?;

        Ok(())
    }

    pub fn load(path: &str) -> Result<Keypair> {
        let public_key = fs::read_to_string(format!("{}.pub", path))?;
        let private_key = fs::read_to_string(path)?;
        Ok(Keypair {
            public: base64::decode(public_key)?,
            private: base64::decode(private_key)?,
        })
    }
}

pub fn generate_keypair() -> Result<Keypair> {
    let snow_keypair = SnowBuilder::new(inbound::NOISE_PARAMS.clone()).generate_keypair()?;
    Ok(Keypair {
        private: snow_keypair.private,
        public: snow_keypair.public,
    })
}
