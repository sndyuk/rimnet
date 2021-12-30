# [**WIP**] Rimnet

Secure container anywahere.
The Secure peer-to-peer overlay TCP/IP network.

- Noise protocol / Asymmetric Encryption
- eBPF

## Usage

### Run

```sh
$ sudo ip netns add rimnet_1
$ sudo ip netns add rimnet_2
$ sudo ip netns exec rimnet_1 ip link set dev lo up
$ sudo ip netns exec rimnet_2 ip link set dev lo up

$ sudo ip link add v-enp2s0 type veth peer name v-eth0
$ sudo ip link set v-eth0 netns rimnet_1
$ sudo ip -n rimnet_1 addr add 10.0.0.0/24 dev v-eth0
$ sudo ip -n rimnet_1 link set v-eth0 up
```

```sh
$ cargo build
$ sudo ip netns exec rimnet_1 sudo RUST_BACKTRACE=full target/debug/rimnet -v -n test-dev --ipv4 10.0.0.3
public key: <KEY>
listening on 127.0.0.1:7891
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

### Send message from example client

#### `nc` command
The peer client will show a handshake error log.

```sh
$ sudo ip netns exec rimnet_1 nc -u 127.0.0.1 7891
Test!<Enter>
<Enter>
```

#### Sample client
The peer client will show a handshake ok log.

```sh
$ sudo ip netns exec rimnet_1 su - `whoami` -c "cd `pwd` && cargo run --example inbound_incomming -- --key <KEY> -p 7891"
```
