use anyhow::*;
use std::net::Ipv4Addr;
use tokio::io::{ReadHalf, WriteHalf};
use tokio_util::codec::FramedRead;
use tracing as log;
use tun::{AsyncDevice, TunPacketCodec};

pub struct NetworkDevice<R> {
    pub reader: R,
    pub writer: WriteHalf<AsyncDevice>,
}

fn create(
    name: &str,
    private_ipv4: &Ipv4Addr,
    mtu: i32,
) -> Result<(ReadHalf<AsyncDevice>, WriteHalf<AsyncDevice>)> {
    let mut devince_name = name;
    #[cfg(target_os = "macos")]
    {
        devince_name = &mut "utun0";
    }

    let mut tun = tun::Configuration::default();
    tun.name(devince_name)
        .address(private_ipv4)
        .layer(tun::Layer::L3)
        .netmask((255, 255, 255, 0))
        .mtu(mtu);

    #[cfg(target_os = "linux")]
    {
        tun.platform(|p| {
            p.packet_information(false);
        });
    }
    tun.up();

    let tun_device = tun::create_as_async(&tun)?;
    log::debug!("device created");
    Ok(tokio::io::split(tun_device))
}

impl NetworkDevice<ReadHalf<AsyncDevice>> {
    pub fn create(
        name: &str,
        private_ipv4: &Ipv4Addr,
        mtu: i32,
    ) -> Result<NetworkDevice<ReadHalf<AsyncDevice>>> {
        let (reader, writer) = create(name, private_ipv4, mtu)?;
        Ok(NetworkDevice { reader, writer })
    }
}

impl NetworkDevice<FramedRead<ReadHalf<AsyncDevice>, TunPacketCodec>> {
    pub fn create(
        name: &str,
        private_ipv4: &Ipv4Addr,
        mtu: i32,
    ) -> Result<NetworkDevice<FramedRead<ReadHalf<AsyncDevice>, TunPacketCodec>>> {
        let (reader, writer) = create(name, private_ipv4, mtu)?;
        let codec = TunPacketCodec::new(false, mtu);
        let framed_reader = FramedRead::new(reader, codec);
        Ok(NetworkDevice {
            reader: framed_reader,
            writer,
        })
    }
}
