extern crate base64;

use anyhow::Result;
use log;
use std::net::{IpAddr, Ipv4Addr};
use tun::AsyncDevice;

pub async fn run(name: &str, private_ipv4: &Ipv4Addr, mtu: i32) -> Result<AsyncDevice> {
    let mut config = tun::Configuration::default();
    config
        .name(name)
        .address(private_ipv4)
        .layer(tun::Layer::L3)
        .netmask((255, 255, 255, 0))
        .mtu(mtu);

    #[cfg(target_os = "linux")]
    {
        config.platform(|p| {
            p.packet_information(false);
        });
    }
    config.up();

    let dev = tun::create_as_async(&config)?;
    log::debug!("tun created");
    Ok(dev)
}
