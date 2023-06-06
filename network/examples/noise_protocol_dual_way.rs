use anyhow::*;
use lazy_static::lazy_static;

use snow::params::NoiseParams;
use snow::Builder;

lazy_static! {
    // TODO Be customizable
    pub static ref NOISE_PARAMS: NoiseParams = "Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}
/// Message exchange using Noise Protocol.

fn main() -> Result<()> {
    let builder_local: Builder<'_> = Builder::new(NOISE_PARAMS.clone());
    let builder_remote: Builder<'_> = Builder::new(NOISE_PARAMS.clone());

    let local_keypair = builder_local.generate_keypair()?;
    let remote_keypair = builder_remote.generate_keypair()?;

    let mut noise_local = builder_local
        .local_private_key(&local_keypair.private)
        .remote_public_key(&remote_keypair.public)
        .build_initiator()?;

    let mut noise_remote = builder_remote
        .local_private_key(&remote_keypair.private)
        //.remote_public_key(&local_keypair.public)
        .build_responder()?;

    let mut buf_local = [0u8; 65535];
    let mut buf_remote = [0u8; 65535];

    println!("handshake");
    let payload_local = [0x00, 0x01, 0x02, 0x03];
    let payload_remote = [0x03, 0x02, 0x01, 0x00];

    // <- s
    let len_local = noise_local.write_message(&payload_local, &mut buf_local)?;
    // -> e, es
    let len_remote = noise_remote.read_message(&buf_local[..len_local], &mut buf_remote)?;
    assert_eq!(&payload_local[..], &buf_remote[..len_remote]);

    let len_remote = noise_remote.write_message(&[], &mut buf_remote)?;
    // <- e, ee
    let len_local = noise_local.read_message(&buf_remote[..len_remote], &mut buf_local)?;
    //assert_eq!(&payload_remote[..], &buf_local[..len_local]);

    let noise_local = noise_local.into_stateless_transport_mode()?;
    let noise_remote = noise_remote.into_stateless_transport_mode()?;

    println!("Case 1");
    let nonce_local = 0;
    let len_local = noise_local.write_message(nonce_local, &payload_local, &mut buf_local)?;

    let len_remote =
        noise_remote.read_message(nonce_local, &buf_local[..len_local], &mut buf_remote)?;
    assert_eq!(&payload_local[..], &buf_remote[..len_remote]);

    println!("Case 2");
    let nonce_remote = 999;
    let len_remote = noise_remote.write_message(nonce_remote, &payload_remote, &mut buf_remote)?;
    let len_local =
        noise_local.read_message(nonce_remote, &buf_remote[..len_remote], &mut buf_local)?;
    assert_eq!(&payload_remote[..], &buf_local[..len_local]);

    Ok(())
}
