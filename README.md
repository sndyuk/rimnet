# [**WIP**] Rimnet

Secure container anywahere.
The Secure peer-to-peer overlay TCP/IP network.

#### Features
- Machine:
  - [x] Linux
  - [ ] MacOS
- [x] Connect the peer agents using Noise protocol.
- [ ] NAT hole punching.
- CLI:
  - [x] `knock` command: to request handshake.
- Web GUI:
  - [ ] TBD
- Reconnect the peer agent if the target agent lost the state:
    - [x] When the agent has cleaned the state cache.
    - [ ] When the target agent has changed the public address.
- [x] Try to connect to a unknown peer via connected peer agents.
- Access control:
  - [ ] Multi Factor Authentication(Handshake) using OIDC CIBA.
  - [ ] Capability based access control.

#### Internal features
  - [ ] Sign using a master key to secure the network.
  - [ ] Extract public I/F for using external datastores to store agents and private networks information.

## Usage

### Machine 1
1. Run the agent.
1-a. Run the agent on a host machine

    ```sh
    $ cargo build -p agent --release && sudo target/release/agent --private-ipv4 10.0.0.3 --public-ipv4 <public IPv4 address of the machine>
    public key: <KEY_1>
    listening on 10.0.254.1:7891
    ```

1-b. Run the agent on a container

    ```sh
    $ cargo build -p agent --release && sudo target/release/agent --private-ipv4 10.0.0.3 --public-ipv4 <public IPv4 address of the container> --external-public-ipv4 <public IPv4 address of the host machine> --external-public-port <public port of the host machine>
    public key: <KEY_2>
    listening on 10.0.254.1:7891
    ```

### Machine 2
2. Run the peer agent on a different machine.

    Same as #1 but use `--private-ipv4 10.0.0.4`.

3. Knock to the peer agent from the new node.

    ```sh
    $ cargo build -p cli --release && target/release/cli knock --private-ipv4 10.0.0.4 --external-public-ipv4 <public IPv4 address of the host machine> --target-exteral-public-ipv4 <public IPv4 address of the target host machine> --public-key <KEY_2>
    ```


### Development (Linux only)

#### Create the sandbox network namespace
```sh
$ ./create_netns.sh

# (!) To delete the network namespace
$ ./clean_netns.sh
```

#### Run the sample agent on the sandbox namespace
```sh
$ cargo build -p agent && sudo ip netns exec rimnet_1 sudo RUST_BACKTRACE=full target/debug/agent -v -n test-dev --private-ipv4 10.0.0.3 --public-ipv4 10.0.254.1
public key: <KEY_1>
listening on 10.0.254.1:7891
```

[Option] To run without `sudo`, apply the net_admin capability to the binary.
```
$ sudo setcap cap_net_admin+epi target/debug/agent
$ sudo ip netns exec rimnet_1 target/debug/agent -v -n test-dev --private-ipv4 10.0.0.3 --public-ipv4 10.0.254.1
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
    $ cargo build -p agent && sudo ip netns exec rimnet_2 sudo RUST_BACKTRACE=full target/debug/agent -v -n test-dev --private-ipv4 10.0.0.4 --public-ipv4 10.0.254.2
    ```

2. Knock to the peer node from the new node.

    ```sh
    $ cargo build -p cli && sudo ip netns exec rimnet_1 target/debug/cli knock --private-ipv4 10.0.0.3 --external-public-ipv4 10.0.254.1 --target-external-public-ipv4 10.0.254.2 --public-key <KEY_1>
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
