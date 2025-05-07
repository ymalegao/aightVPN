#!/bin/bash

PORT=443
TUN_IF="tun0"
PSK="your_psk_here"
CERT="server.crt"
KEY="server.key"

# 1. Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# 2. Bring up TUN interface with IP
sudo ip link set $TUN_IF up || sudo ip tuntap add dev $TUN_IF mode tun
sudo ip addr flush dev $TUN_IF
sudo ip addr add 10.8.0.1/24 dev $TUN_IF

# 3. Setup NAT using iptables (replace eth0 if needed)
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE

# 4. Run VPN server
sudo ./bazel-bin/vpn_server $PORT $TUN_IF "$PSK" $CERT $KEY

