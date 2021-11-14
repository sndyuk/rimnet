extern crate base64;

use anyhow::Result;
use log;

use tun::AsyncDevice;

pub async fn run_tun(name: &str, mtu: i32) -> Result<AsyncDevice> {
    let mut config = tun::Configuration::default();
    config.name(name);
    config
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .mtu(mtu)
        .up();
    let dev = tun::create_as_async(&config)?;
    log::debug!("tun created");
    Ok(dev)
}
