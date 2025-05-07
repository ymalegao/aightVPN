#!/bin/bash

PORT=443
TUN_IF="tun0"
PSK="your_psk_here"
CERT="server.crt"
KEY="server.key"

# 1. Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# 2. Run VPN server in background
sudo ./bazel-bin/vpn_server $PORT $TUN_IF "$PSK" $CERT $KEY &

# 3. Wait for tun0 to be created
echo "Waiting for $TUN_IF..."
while ! ip link show $TUN_IF &>/dev/null; do sleep 0.2; done
echo "$TUN_IF is up"

# 4. Assign IP and NAT
sudo ip addr flush dev $TUN_IF
sudo ip addr add 10.8.0.1/24 dev $TUN_IF
sudo ip link set $TUN_IF up
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
