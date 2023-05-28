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
  - [x] `cert` command: to issue a client cert.
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
1. Issue client cert

    ```sh
    $ cargo build -p cli --release && target/release/cli cert -n agent1
    ```

2. Run the agent.
2-a. Run the agent on a host machine

    ```sh
    $ cargo build -p agent --release && sudo target/release/agent --private-ipv4 10.0.0.3 --public-ipv4 <public IPv4 address of the machine> --client-cert agent1
    public key: <KEY_1>
    listening on 10.0.254.1:7891
    ```

    Or you can run the agent on a linux container:

    ```sh
    # Inside a container
    # e.g.
    # $ docker run --privileged -it --rm -v `pwd`/.:/usr/src/app -p 7991:7891 rust:1.63
    # > cd /usr/src/app
    # > cargo build -p agent --release && target/release/agent --private-ipv4 10.0.0.3 --public-ipv4 172.17.0.2 --external-public-ipv4 192.168.1.5 --external-public-port 7991
    $ cargo build -p agent --release && target/release/agent --private-ipv4 10.0.0.3 --public-ipv4 <public IPv4 address of the container> --external-public-ipv4 <public IPv4 address of the host machine> --external-public-port <public port of the host machine>
    public key: <KEY_2>
    listening on 10.0.254.1:7891
    ```

### Machine 2
1. Issue client cert

    ```sh
    $ cargo build -p cli --release && target/release/cli cert -n agent2
    ```

2. Run the peer agent on a different machine.

    Same as #1 but use `--private-ipv4 10.0.0.4`.

3. Knock to the peer agent from the new node.

    ```sh
    $ cargo build -p cli --release && target/release/cli knock-request --public-ipv4 <public IPv4 address of the machine> --target-public-ipv4 <public IPv4 address of the target host machine>
    ```

### Validation the environment
4. Run a stub server on the machine 1

    ```sh
    $ nc -l 10.0.0.4 8080
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
$ cargo build -p agent && sudo ip netns exec rimnet_1 sudo RUST_BACKTRACE=full target/debug/agent -v -n test-dev --private-ipv4 10.0.0.3 --public-ipv4 10.0.254.1 --client-cert agent1
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

#### Run dummy TCP server first for the following examples

```sh
$ sudo ip netns exec rimnet_1 nc -l 10.0.0.3 8080
```

#### Example 1. Confirm running the agent
The peer client will show the log "The target peer(10.0.0.1) not found".

```sh
$ sudo ip netns exec rimnet_1 nc -u 10.0.0.1 7891
Test!<Enter>
<Enter>
```

#### Example 2. Send ping packet using the private network

1. Run a peer node
The node is going to run on the new sandbox network `rimnet_2`.

    ```sh
    $ cargo build -p agent && sudo ip netns exec rimnet_2 sudo RUST_BACKTRACE=full target/debug/agent -v -n test-dev --private-ipv4 10.0.0.4 --public-ipv4 10.0.254.2 --client-cert agent2
    ```

2. Knock to the peer node from the new node.
    It will only accept the incomming request from the peer node(10.0.0.4) to the source node(10.0.0.3).
    ```sh
    $ cargo build -p cli && sudo ip netns exec rimnet_1 target/debug/cli knock-request --public-ipv4 10.0.254.1 --target-public-ipv4 10.0.254.2
    ```

    Opposite as well.
    ```sh
    $ cargo build -p cli && sudo ip netns exec rimnet_2 target/debug/cli knock-request --public-ipv4 10.0.254.2 --target-public-ipv4 10.0.254.1
    ...
    [Inbound / incomming] Session established
    ```

3. Send a ping packet.

    ```sh
    $ sudo ip netns exec rimnet_2 ping 10.0.0.3 -c 1
    PING 10.0.0.3 (10.0.0.3) 56(84) bytes of data.
    64 bytes from 10.0.0.3: icmp_seq=1 ttl=64 time=2.17 ms

    --- 10.0.0.3 ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 2.170/2.170/2.170/0.000 ms
    ```

4. Send HTTP request

    ```sh
    $ sudo ip netns exec rimnet_2 curl http://10.0.0.3:8080
    ```
    (!) It won't be terminated since the target server, ran by nc command above, doesn't have HTTP feature.
    The target server should output the following dump:
    ```sh
    $ sudo ip netns exec rimnet_1 nc -l 10.0.0.3 8080
    GET / HTTP/1.1
    Host: 10.0.0.3:8080
    User-Agent: curl/7.61.1
    Accept: */*
    ```

#### Example 3. Manually emulate an inbound trafic
The peer client will show a handshake ok log.

From the same network
```sh
$ sudo ip netns exec rimnet_1 su - `whoami` -c "cd `pwd` && cargo run --example emulate_inbound_trafic"
```

From the host machine
```sh
$ cargo run --example emulate_inbound_trafic -- --host-ipv4 10.0.254.254
```


---
## Performance
* w/ Rimnet (agent A -> agent B on the same machine)
    Agent A
    ```
    $ sudo ip netns exec rimnet_2 iperf -s
    ```

    1) with `--mtu 1500` option
    Agent B
    ```
    $ sudo ip netns exec rimnet_1 iperf -c 10.0.0.4
    [  1] local 10.0.0.3 port 59960 connected with 10.0.0.4 port 5001
    [ ID] Interval       Transfer     Bandwidth
    [  1] 0.00-10.09 sec   374 MBytes   311 Mbits/sec
    ```

    2) with `--mtu 60000` option
    Agent B
    ```
    $ sudo ip netns exec rimnet_1 iperf -c 10.0.0.4
    [  1] local 10.0.0.3 port 59960 connected with 10.0.0.4 port 5001
    [ ID] Interval       Transfer     Bandwidth
    [  1] 0.00-10.02 sec  3.28 GBytes  2.81 Gbits/sec
    ```

* w/o Rimnet (Host machine -> Docker container on the same machine)
    ```
    [  1] local 172.17.0.2 port 50001 connected with 172.17.0.1 port 49394
    [ ID] Interval       Transfer     Bandwidth
    [  1] 0.0000-10.0005 sec  32.4 GBytes  27.8 Gbits/sec
    ```

* w/o Rimnet (Host machine -> Machine B on the same local network)
    `mtu 1500`

    ```
    $ sudo ip netns exec rimnet_1 iperf -c 10.0.0.4
    [  1] local 10.0.0.3 port 59960 connected with 10.0.0.4 port 5001
    [ ID] Interval       Transfer     Bandwidth
    [  1] 0.00-10.03 sec  46.3 MBytes  38.7 Mbits/sec
    ```
