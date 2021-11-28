# [**WIP**] Rimnet

Secure container anywahere.
The Secure peer-to-peer overlay TCP/IP network.

- Noise protocol / Asymmetric Encryption
- eBPF

## Usage

### Run
```sh
$ cargo build
$ sudo RUST_BACKTRACE=full target/debug/rimnet -v -n test-dev
public key: <KEY>
listening on 127.0.0.1:7891
```

[Option] To run without `sudo`, apply the net_admin capability to the binaly.
```
$ sudo setcap cap_net_admin+epi ./target/debug/rimnet
$ target/debug/rimnet -v -n test-dev
```

### Trace packets
```sh
$ sudo tcpdump -i test-dev
```

### Send message from example client
```sh
$ cargo run --example client -- --key <KEY> -p 7891
```
