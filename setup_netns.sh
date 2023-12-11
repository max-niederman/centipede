#!/usr/bin/env bash

# create the peer namespace
ip netns add peer

# create the veth pair
ip link add name vethpeer type veth peer name veth0 netns peer

# set up the addresses
ip addr add 10.0.1.1/24 dev vethpeer
ip -n peer addr add 10.0.1.2/24 dev veth0

# bring up the interfaces
ip link set vethpeer up
ip -n peer link set veth0 up