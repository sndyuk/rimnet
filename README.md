# [**WIP**] Rimnet

Secure container anywahere.
The Secure peer-to-peer overlay TCP/IP network.

- Noise protocol / Asymmetric Encryption
- eBPF

## Usage

### Run

#### Create the sandbox network namespace
```sh
$ ./create_netns.sh

# (!) To delete the network namespace
$ ./clean_netns.sh
```

#### Run the agent on the sandbox namespace
```sh
$ cargo build
$ sudo ip netns exec rimnet_1 sudo RUST_BACKTRACE=full target/debug/rimnet -v -n test-dev --ipv4 10.0.0.3
public key: <KEY>
listening on 10.0.254.1:7891
```

[Option] To run without `sudo`, apply the net_admin capability to the binaly.
```
$ sudo setcap cap_net_admin+epi ./target/debug/rimnet
$ sudo ip netns exec rimnet_1 target/debug/rimnet -v -n test-dev --ipv4 10.0.0.3
```

### Trace packets
```sh
$ sudo ip netns exec rimnet_1 sudo tcpdump -i test-dev
```

### Send message to the agent

#### Run dummy TCP client first for the following examples

```sh
$ sudo ip netns exec rimnet_1 nc -l 10.0.0.3 8080
```

#### Example 1. Confirm running the agent
The peer client will show a handshake error log.

```sh
$ sudo ip netns exec rimnet_1 nc -u 10.0.0.1 7891
Test!<Enter>
<Enter>
```

#### Example 2. Emulate inbound trafic
The peer client will show a handshake ok log.

From the same network
```sh
$ sudo ip netns exec rimnet_1 su - `whoami` -c "cd `pwd` && cargo run --example inbound_incomming -- --key <KEY> -p 7891"
```

From the host machine
```sh
$ cargo run --example inbound_incomming -- --key <KEY> --host-ipv4 10.0.254.254 -p 7891
```
