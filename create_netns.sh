#!/bin/env bash

# Create network namespace
sudo ip netns add rimnet_1
sudo ip netns exec rimnet_1 ip link set dev lo up

# Create the veth
sudo ip link add name veth0-rimnet type veth peer name veth0-rimnet-br
sudo ip link add name veth1-rimnet type veth peer name veth1-rimnet-br

# Move the peer to rimnet_1
sudo ip link set veth1-rimnet netns rimnet_1

# Assign IPv4 address
sudo ip addr add 10.0.254.254/24 dev veth0-rimnet
sudo ip netns exec rimnet_1 sudo ip addr add 10.0.254.1/24 dev veth1-rimnet

# Create bridge from host to rimnet_1
sudo ip link add br-rimnet type bridge
sudo ip link set dev veth0-rimnet-br master br-rimnet
sudo ip link set dev veth1-rimnet-br master br-rimnet

# Up
sudo ip link set veth0-rimnet up
sudo ip link set veth0-rimnet-br up
sudo ip netns exec rimnet_1 ip link set veth1-rimnet up
sudo ip link set veth1-rimnet-br up
sudo ip link set br-rimnet up

# Configure routing
sudo iptables -t nat -A POSTROUTING --source 10.0.254.0/24 -j MASQUERADE
sudo iptables -t filter -A FORWARD -d 10.0.254.0/24 -j ACCEPT

sudo ip netns exec rimnet_1 ip route add default via 10.0.254.254

# Configure firewall
firewall-cmd --zone=trusted --change-interface=br-rimnet
firewall-cmd --zone=trusted --change-interface=veth0-rimnet
sudo ip netns exec rimnet_1 firewall-cmd --zone=trusted --change-interface=veth1-rimnet
