# create the veth pair
ip link add name veth1 type veth peer name veth2

# set up the main namespace
ip addr add 10.0.1.1/24 dev veth1

# create the peer namespace
ip netns add peer

# move the peer veth into the peer namespace
ip link set veth2 netns peer

# set up the peer namespace
ip -n peer addr add 10.0.1.2/24 dev veth2

# bring up the interfaces
ip link set veth1 up
ip -n peer link set veth2 up