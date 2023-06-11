use anyhow::*;
use base64::{engine::general_purpose, Engine as _};
use lazy_static::lazy_static;
use regex::Regex;
use snow::params::NoiseParams;
use snow::Builder as SnowBuilder;
use std::fs;

lazy_static! {
    pub static ref NOISE_PARAMS: NoiseParams = "Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
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

        let public_key = general_purpose::STANDARD.encode(&self.public);
        let private_key = general_purpose::STANDARD.encode(&self.private);
        fs::write(format!("{}.pub", name), public_key)?;
        fs::write(name, private_key)?;

        Ok(())
    }

    pub fn load(path: &str) -> Result<Keypair> {
        let public_key = fs::read_to_string(format!("{}.pub", path))?;
        let private_key = fs::read_to_string(path)?;
        Ok(Keypair {
            public: general_purpose::STANDARD.decode(public_key)?,
            private: general_purpose::STANDARD.decode(private_key)?,
        })
    }
}

pub fn generate_keypair() -> Result<Keypair> {
    let snow_keypair = SnowBuilder::new(NOISE_PARAMS.clone()).generate_keypair()?;
    Ok(Keypair {
        private: snow_keypair.private,
        public: snow_keypair.public,
    })
}
