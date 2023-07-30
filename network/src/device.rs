use anyhow::*;
use std::net::Ipv4Addr;
use tokio::io::{ReadHalf, WriteHalf};
use tokio_util::codec::FramedRead;
use tracing as log;
use tun::{AsyncDevice, TunPacketCodec, Device};
use std::process::Command;

pub static SYNC_PACKET: [u8; 2] = [0x00, 0x01];

pub struct NetworkDevice<R> {
    pub reader: R,
    pub writer: WriteHalf<AsyncDevice>,
}

fn create(
    name: &str,
    private_ipv4: &Ipv4Addr,
    mtu: i32,
) -> Result<(ReadHalf<AsyncDevice>, WriteHalf<AsyncDevice>)> {
    let mut device_name = name;
    #[cfg(target_os = "macos")]
        {
            log::info!(
                "MacOS detected, using \"utunN\" instead of the specified device name \"{}\"",
                device_name
            );
            device_name = &mut "utun0";
        }
    #[cfg(target_os = "linux")]
    let device_name = name;

    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    let mut tun = tun::Configuration::default();
    tun.name(device_name)
        .address(private_ipv4)
        .layer(tun::Layer::L3)
        .netmask(netmask)
        .mtu(mtu);

    #[cfg(target_os = "linux")]
    {
        tun.platform(|p| {
            p.packet_information(true);
        });
    }
    tun.up();

    let tun_device = tun::create_as_async(&tun)?;
    log::debug!("device created");

    #[cfg(target_os = "macos")]
    {
        log::info!(
            "MacOS detected, using \"{}\" instead of the specified device name \"{}\"",
            tun_device.get_ref().name(),
            device_name,
        );

        // Configure route table to pass through the subnet traffic to the utun device.
        let subnet = Ipv4Addr::from(u32::from_be_bytes(private_ipv4.octets()) & u32::from_be_bytes(netmask.octets()));
        let output = Command::new("route")
            .arg("-n")
            .arg("add")
            .arg("-net")
            .arg(format!("{}/24", subnet))
            .arg("-interface")
            .arg(tun_device.get_ref().name())
            .output()
            .expect("Could not add route for the utun device");
            log::info!("{}", String::from_utf8_lossy(&output.stdout).trim());
    }

    Ok(tokio::io::split(tun_device))
}

impl NetworkDevice<FramedRead<ReadHalf<AsyncDevice>, TunPacketCodec>> {
    pub fn create(
        name: &str,
        private_ipv4: &Ipv4Addr,
        mtu: i32,
    ) -> Result<NetworkDevice<FramedRead<ReadHalf<AsyncDevice>, TunPacketCodec>>> {
        let (reader, writer) = create(name, private_ipv4, mtu)?;
        let codec = TunPacketCodec::new(true, mtu);
        let framed_reader = FramedRead::new(reader, codec);
        Ok(NetworkDevice {
            reader: framed_reader,
            writer,
        })
    }
}
