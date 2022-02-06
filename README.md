# [**WIP**] Rimnet

Secure container anywahere.
The Secure peer-to-peer overlay TCP/IP network.

- Noise protocol / Asymmetric Encryption
- Ethereum
- eBPF

## Usage

### Run

#### Create the sandbox network namespace
```sh
$ ./create_netns.sh

# (!) To delete the network namespace
$ ./clean_netns.sh
```

#### Run the sample agent on the sandbox namespace
```sh
$ cargo build --examples
$ sudo ip netns exec rimnet_1 sudo RUST_BACKTRACE=full target/debug/examples/agent -v -n test-dev --private-ipv4 10.0.0.3 --public-ipv4 10.0.254.1
public key: <KEY_1>
listening on 10.0.254.1:7891
```

[Option] To run without `sudo`, apply the net_admin capability to the binary.
```
$ sudo setcap cap_net_admin+epi target/debug/examples/agent
$ sudo ip netns exec rimnet_1 target/debug/examples/agent -v -n test-dev --private-ipv4 10.0.0.3 --public-ipv4 10.0.254.1
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

#### Example 2. Manually emulate an inbound trafic
The peer client will show a handshake ok log.

From the same network
```sh
$ sudo ip netns exec rimnet_1 su - `whoami` -c "cd `pwd` && cargo run --example inbound_incomming -- --key <KEY_1> -p 7891"
```

From the host machine
```sh
$ cargo run --example inbound_incomming -- --key <KEY_1> --host-ipv4 10.0.254.254 -p 7891
```


#### Example 3. Send ping packet using the private network

1. Run a peer node
The node is going to run on the new sandbox network `rimnet_2`.

    ```sh
    $ cargo build --examples && sudo ip netns exec rimnet_2 sudo RUST_BACKTRACE=full target/debug/examples/agent -v -n test-dev --private-ipv4 10.0.0.4 --public-ipv4 10.0.254.2
    ```

2. Knock to the peer node from the new node.

    ```sh
    $ cargo build --examples && sudo ip netns exec rimnet_1 target/debug/examples/knock_knock --private-ipv4 10.0.0.3 --public-ipv4 10.0.254.1 --target-public-ipv4 10.0.254.2 --public-key <KEY_1>
    ```

3. Send ping packet.

    ```sh
    $ sudo ip netns exec rimnet_2 ping 10.0.0.3 -c 1
    PING 10.0.0.3 (10.0.0.3) 56(84) bytes of data.
    64 bytes from 10.0.0.3: icmp_seq=1 ttl=64 time=2.17 ms

    --- 10.0.0.3 ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 2.170/2.170/2.170/0.000 ms
    ```

#### TODO
- [ ] Extract public I/F for using external datastores to store agents and private networks information
- [ ] TBD
