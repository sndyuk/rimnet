#!/bin/env bash

# Down
sudo ip link set veth0-rimnet down
sudo ip link set veth0-rimnet-br down
sudo ip netns exec rimnet_1 ip link set veth1-rimnet down
sudo ip link set veth1-rimnet-br down
sudo ip link set br-rimnet down

# Clean the bridge from host to rimnet_1
sudo ip link delete br-rimnet

# Clean veth peer
sudo ip link delete veth0-rimnet
sudo ip netns exec rimnet_1 sudo ip link delete veth1-rimnet

# Clean network namespace
sudo ip netns del rimnet_1

# Configure routing
sudo iptables -t nat -D POSTROUTING -s 10.0.254.0/24 -j MASQUERADE
sudo iptables -t filter -D FORWARD -d 10.0.254.0/24 -j ACCEPT
